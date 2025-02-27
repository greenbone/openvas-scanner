// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::interpreter::ForkingInterpreter;
use std::path::PathBuf;

use crate::models::{Host, Parameter, Protocol, ScanID};
use crate::nasl::syntax::{Loader, NaslValue};
use crate::nasl::utils::context::Target;
use crate::nasl::utils::{Executor, Register};
use crate::scheduling::Stage;
use crate::storage::error::StorageError;
use crate::storage::items::kb::{KbContext, KbContextKey, KbItem, KbKey};
use crate::storage::items::nvt::Nvt;
use crate::storage::{ContextStorage, Retriever};
use futures::StreamExt;
use tracing::{trace, warn};

use crate::nasl::prelude::*;

use super::ExecuteError;
use super::{
    error::{ScriptResult, ScriptResultKind},
    ScannerStack,
};

/// Runs a single VT to completion on a single host.
pub struct VTRunner<'a, S: ScannerStack> {
    storage: &'a S::Storage,
    loader: &'a S::Loader,
    executor: &'a Executor,

    target: &'a Host,
    vt: &'a Nvt,
    stage: Stage,
    param: Option<&'a Vec<Parameter>>,
    scan_id: ScanID,
}

impl<'a, Stack: ScannerStack> VTRunner<'a, Stack>
where
    Stack::Storage: ContextStorage,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        storage: &'a Stack::Storage,
        loader: &'a Stack::Loader,
        executor: &'a Executor,
        target: &'a Host,
        vt: &'a Nvt,
        stage: Stage,
        param: Option<&'a Vec<Parameter>>,
        scan_id: ScanID,
    ) -> Result<ScriptResult, ExecuteError> {
        let s = Self {
            storage,
            loader,
            executor,
            target,
            vt,
            stage,
            param,
            scan_id,
        };
        s.execute().await
    }

    fn parameter(
        &self,
        parameter: &Parameter,
        _register: &mut Register,
    ) -> Result<(), ExecuteError> {
        // TODO: implement
        Err(ExecuteError::Parameter(parameter.clone()))
    }

    fn set_parameters(&mut self, register: &mut Register) -> Result<(), ExecuteError> {
        if let Some(params) = &self.param {
            for p in params.iter() {
                self.parameter(p, register)?;
            }
        }
        Ok(())
    }

    fn check_key<A, B, C>(
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
        // TODO: Set span again
        // let _span = error_span!("kb_item", %key).entered();
        let result = match self.storage.retrieve(key) {
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

    fn check_keys(&self, vt: &Nvt) -> Result<(), ScriptResultKind> {
        let key = self.generate_key();
        let check_required_key = |k: &str| {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || Some(ScriptResultKind::MissingRequiredKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingRequiredKey(k.into())),
            )
        };
        for k in &vt.required_keys {
            check_required_key(k)?
        }

        let check_mandatory_key = |k: &str| {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || Some(ScriptResultKind::MissingMandatoryKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingMandatoryKey(k.into())),
            )
        };
        for k in &vt.mandatory_keys {
            check_mandatory_key(k)?
        }

        let check_exclude_key = |k: &str| {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || None,
                |_| Some(ScriptResultKind::ContainsExcludedKey(k.into())),
                |_| None,
            )
        };
        for k in &vt.excluded_keys {
            check_exclude_key(k)?
        }

        let check_port = |pt: Protocol, port: &str| {
            let kbk = KbKey::Port(pt.to_string(), port.to_string());
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
        };
        for k in &vt.required_ports {
            check_port(Protocol::TCP, k)?
        }
        for k in &vt.required_udp_ports {
            check_port(Protocol::UDP, k)?
        }

        Ok(())
    }

    // TODO: probably better to enhance ContextKey::Scan to contain target and scan_id?
    fn generate_key(&self) -> KbContext {
        (
            crate::storage::ScanID(self.scan_id.clone()),
            crate::storage::Target(self.target.clone()),
        )
    }

    async fn get_result_kind(
        &self,
        filename: PathBuf,
        code: &str,
        register: Register,
    ) -> ScriptResultKind {
        if let Err(e) = self.check_keys(self.vt) {
            return e;
        }
        let mut target = Target::default();
        target.set_target(self.target.clone());

        let context = Context::new(
            crate::storage::ScanID(self.scan_id.clone()),
            target,
            filename,
            self.storage,
            self.loader,
            self.executor,
        );
        let mut results = Box::pin(ForkingInterpreter::new(code, register, &context).stream());
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
        let code = self.loader.load(&self.vt.filename)?;
        let mut register = Register::default();
        self.set_parameters(&mut register)?;

        // currently scans are limited to the target as well as the id.
        tracing::debug!("running");
        let kind = self
            .get_result_kind(self.vt.filename.clone().into(), &code, register)
            .await;
        tracing::debug!(result=?kind, "finished");
        Ok(ScriptResult {
            oid: self.vt.oid.clone(),
            filename: self.vt.filename.clone(),
            stage: self.stage,
            kind,
            target: self.target.clone(),
        })
    }
}
