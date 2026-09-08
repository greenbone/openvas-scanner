// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::{Parameter, Protocol, VTData};
use crate::nasl::interpreter::{ForkingInterpreter, InterpreterError};
use crate::nasl::utils::Register;
use crate::nasl::utils::lookup_keys::SCRIPT_PARAMS;
use crate::nasl::utils::scan_ctx::TargetId;
use crate::scheduling::Stage;
use crate::storage::error::StorageError;
use crate::storage::items::kb::{self, KbContext, KbContextKey, KbItem, KbKey};
use futures::StreamExt;
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

    async fn get_result_kind(&self, code: Code, register: Register) -> ScriptResultKind {
        if let Err(e) = self.check_keys(self.vt).await {
            return e;
        }
        let script_ctx = ScriptCtx::new(
            &self.scan_ctx,
            self.target,
            Some(self.vt.clone()),
            (&self.vt.filename).into(),
        );
        let ast = code.parse().emit_errors();
        if let Err(errs) = ast {
            return ScriptResultKind::Error(InterpreterError::syntax_error(errs));
        }
        let ast = ast.unwrap();

        let mut results =
            Box::pin(ForkingInterpreter::new(ast, register, &self.scan_ctx, script_ctx).stream());
        while let Some(r) = results.next().await {
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
        let code = Code::load(self.scan_ctx.loader(), &self.vt.filename)?;
        let mut register = Register::default();
        self.set_parameters(&mut register)?;

        // currently scans are limited to the target as well as the id.
        tracing::debug!("running");
        let kind = self.get_result_kind(code, register).await;
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
