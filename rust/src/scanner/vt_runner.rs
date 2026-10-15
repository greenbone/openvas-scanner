// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashSet;

use crate::models::{Parameter, Protocol, VTData};
use crate::nasl::interpreter::{ForkingInterpreter, InterpreterError};
use crate::nasl::syntax::grammar::Ast;
use crate::nasl::utils::Register;
use crate::nasl::utils::ctx::TargetId;
use crate::nasl::utils::lookup_keys::SCRIPT_PARAMS;
use crate::nasl::utils::mtime::MtimeStatus;
use crate::scheduling::Stage;
use crate::storage::error::StorageError;
use crate::storage::items::kb::{self, KbContext, KbContextKey, KbItem, KbKey};
use tracing::{trace, warn};

use crate::nasl::prelude::*;

use super::ExecuteError;
use super::error::{ScriptResult, ScriptResultKind};

/// Runs a single VT to completion on a single host.
pub struct VTRunner<'a> {
    target: TargetId,
    vt: &'a VTData,
    stage: Stage,
    param: Option<&'a Vec<Parameter>>,

    scan_ctx: &'a ScanCtx<'a>,
}

impl<'a> VTRunner<'a> {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        target: TargetId,
        vt: &'a VTData,
        stage: Stage,
        param: Option<&'a Vec<Parameter>>,
        scan_ctx: &'a ScanCtx<'a>,
    ) -> Result<ScriptResult, ExecuteError> {
        let s = Self {
            target,
            vt,
            stage,
            param,

            scan_ctx,
        };
        s.execute().await
    }

    fn set_parameters(&mut self, register: &mut Register) -> Result<(), ExecuteError> {
        if let Some(params) = &self.param {
            for p in params.iter() {
                register.add_global_var(
                    format!("{}_{}", SCRIPT_PARAMS, p.id).as_str(),
                    NaslValue::String(p.value.clone()),
                );
            }
        }
        Ok(())
    }

    async fn check_key<A, B, C>(
        &self,
        key: &KbContextKey,
        result_none: A,
        result_some: B,
        result_err: C,
    ) -> Result<(), ScriptResultKind>
    where
        A: Fn() -> Option<ScriptResultKind>,
        B: Fn(Vec<KbItem>) -> Option<ScriptResultKind>,
        C: Fn(StorageError) -> Option<ScriptResultKind>,
    {
        let result = match self.scan_ctx.storage().retrieve(key).await {
            Ok(x) => {
                if let Some(x) = x {
                    result_some(x)
                } else {
                    trace!("not found");
                    result_none()
                }
            }
            Err(e) => {
                warn!(error=%e, "storage error");
                result_err(e)
            }
        };
        match result {
            None => Ok(()),
            Some(x) => Err(x),
        }
    }

    async fn check_keys(&self, vt: &VTData) -> Result<(), ScriptResultKind> {
        let key = self.generate_key();
        for k in &vt.required_keys {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || Some(ScriptResultKind::MissingRequiredKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingRequiredKey(k.into())),
            )
            .await?
        }

        for k in &vt.mandatory_keys {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || Some(ScriptResultKind::MissingMandatoryKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingMandatoryKey(k.into())),
            )
            .await?
        }

        for k in &vt.excluded_keys {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || None,
                |_| Some(ScriptResultKind::ContainsExcludedKey(k.into())),
                |_| None,
            )
            .await?
        }

        let check_port = async |pt: Protocol, port: &str| {
            let kbk = match pt {
                Protocol::UDP => KbKey::Port(kb::Port::Udp(port.to_string())),
                Protocol::TCP => KbKey::Port(kb::Port::Tcp(port.to_string())),
            };
            self.check_key(
                &KbContextKey(key.clone(), kbk),
                || Some(ScriptResultKind::MissingPort(pt, port.to_string())),
                |mut v| {
                    if !v.is_empty() && v.pop().unwrap().into() {
                        None
                    } else {
                        Some(ScriptResultKind::MissingPort(pt, port.to_string()))
                    }
                },
                |_| Some(ScriptResultKind::MissingPort(pt, port.to_string())),
            )
            .await
        };
        for k in &vt.required_ports {
            check_port(Protocol::TCP, k).await?
        }
        for k in &vt.required_udp_ports {
            check_port(Protocol::UDP, k).await?
        }

        Ok(())
    }

    /// Check if include file mtime is valid. This is done at interpretation, since
    /// we need to parse the nasl file and later look into includes and nested includes.
    async fn check_include_mtimes(&self, ast: &Ast) -> Result<(), ScriptResultKind> {
        let mut visited = HashSet::new();
        let filename = std::path::PathBuf::from(&self.vt.filename);
        let mut pending: Vec<_> = ast
            .iter_includes()
            .map(|i| (filename.clone(), i.path.clone()))
            .collect();

        while let Some((including_file, include)) = pending.pop() {
            // Recurse into the included file to discover any further nested includes. If it
            // can't be loaded or parsed, the real error will surface when the interpreter
            // actually resolves the include, so we don't fail the mtime check here.
            let Ok(file) = include.load(self.scan_ctx.loader(), &including_file) else {
                continue;
            };
            if !visited.insert(file.id()) {
                continue;
            }
            let path = file.source().path().to_owned();
            match self.scan_ctx.storage().check_mtime(&path).await {
                Ok(MtimeStatus::UpToDate) => {}
                Ok(MtimeStatus::Modified {
                    file,
                    stored,
                    current,
                }) => {
                    return Err(ScriptResultKind::MtimeCheckFailed(format!(
                        "The VT {file} has been modified since it has mtime {current} newer than the stored {stored}"
                    )));
                }
                Err(reason) => return Err(ScriptResultKind::MtimeCheckFailed(reason)),
            }
            if let Ok(included_ast) = file.parse().result() {
                pending.extend(
                    included_ast
                        .iter_includes()
                        .map(|i| (path.clone(), i.path.clone())),
                );
            }
        }
        Ok(())
    }

    // TODO: probably better to enhance ContextKey::Scan to contain target and scan_id?
    fn generate_key(&self) -> KbContext {
        let original_target_str = self
            .scan_ctx
            .target_by_id(self.target)
            .original_target_str();
        (
            self.scan_ctx.scan().clone(),
            crate::storage::Target(original_target_str.into()),
        )
    }

    async fn execute_inner(&self, file: NaslFile<'_>, register: Register) -> ScriptResultKind {
        if let Err(e) = self.check_keys(self.vt).await {
            return e;
        }
        let script_ctx = ScriptCtx::new(self.scan_ctx, self.target, self.vt.clone());
        let ast = file.parse().emit_errors();
        if let Err(errs) = ast {
            return ScriptResultKind::Error(InterpreterError::syntax_error(errs));
        }
        let ast = ast.unwrap();

        if let Err(e) = self.check_include_mtimes(&ast).await {
            return e;
        }

        let mut interpreter = ForkingInterpreter::new(ast, register, self.scan_ctx, script_ctx);
        while let Some(r) = interpreter.next().await {
            match r {
                Ok(NaslValue::Exit(x)) => return ScriptResultKind::ReturnCode(x),
                Err(e) => return ScriptResultKind::Error(e),
                Ok(x) => {
                    trace!(statement_result=?x);
                }
            }
        }
        ScriptResultKind::ReturnCode(0)
    }

    async fn execute(mut self) -> Result<ScriptResult, ExecuteError> {
        let file = self.scan_ctx.loader().load_nasl(&self.vt.filename)?;
        let mut register = Register::default();
        self.set_parameters(&mut register)?;

        // currently scans are limited to the target as well as the id.
        tracing::debug!("running");
        let kind = self.execute_inner(file, register).await;
        tracing::debug!(result=?kind, "finished");
        Ok(ScriptResult {
            oid: self.vt.oid.clone(),
            filename: self.vt.filename.clone(),
            stage: self.stage,
            kind,
            target: self
                .scan_ctx
                .target_by_id(self.target)
                .original_target_str()
                .into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        nasl::{
            nasl_std_executor,
            utils::ctx::{CtxTargets, Ports, Target},
        },
        scanner::preferences::preference::ScanPrefs,
        storage::{ScanID, inmemory::InMemoryStorage},
    };
    use std::path::Path;

    #[tokio::test]
    async fn include_checks_resolve_nested_files_relative_to_their_parent() {
        let loader = Loader::test()
            .with_file(
                "plugins/main.nasl",
                r#"include("a/first.inc"); include("b/first.inc");"#.into(),
            )
            .with_file("a/first.inc", r#"include("second.inc");"#.into())
            .with_file("b/first.inc", r#"include("second.inc");"#.into())
            .with_file("a/second.inc", r#"include("first.inc");"#.into())
            .with_file("b/second.inc", String::new())
            .build();
        let storage = InMemoryStorage::new();
        let executor = nasl_std_executor();
        let (targets, target) = CtxTargets::single(Target::localhost(), Ports::default());
        let ctx = ScanCtx::new(
            ScanID::default(),
            targets,
            &storage,
            &loader,
            &executor,
            ScanPrefs::new(),
            Vec::new(),
            None,
        );
        let vt = VTData::from_filename("plugins/main.nasl");
        let ast = ctx
            .loader()
            .load_nasl(&vt.filename)
            .unwrap()
            .parse()
            .result()
            .unwrap();
        let runner = VTRunner {
            target,
            vt: &vt,
            stage: Stage::NonEvasive,
            param: None,
            scan_ctx: &ctx,
        };

        assert!(runner.check_include_mtimes(&ast).await.is_ok());
        let sources = ctx.loader().source_files();
        for path in ["a/first.inc", "a/second.inc", "b/first.inc", "b/second.inc"] {
            assert!(sources.id(Path::new(path)).is_some(), "{path}");
        }
    }
}
