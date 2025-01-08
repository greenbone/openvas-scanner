// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::{Host, Parameter, Protocol, ScanId};
use crate::nasl::syntax::{Loader, NaslValue};
use crate::nasl::utils::context::Target;
use crate::nasl::utils::{Executor, Register};
use crate::scheduling::Stage;
use crate::storage::item::Nvt;
use crate::storage::{types::Primitive, Retriever, Storage};
use crate::storage::{ContextKey, Field, Retrieve, StorageError};
use futures::StreamExt;
use tracing::{error_span, trace, warn};

use crate::nasl::interpreter::CodeInterpreter;
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
    scan_id: &'a ScanId,
}

impl<'a, Stack: ScannerStack> VTRunner<'a, Stack> {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        storage: &'a Stack::Storage,
        loader: &'a Stack::Loader,
        executor: &'a Executor,
        target: &'a Host,
        vt: &'a Nvt,
        stage: Stage,
        param: Option<&'a Vec<Parameter>>,
        scan_id: &'a ScanId,
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
        key: &ContextKey,
        kb_key: &str,
        result_none: A,
        result_some: B,
        result_err: C,
    ) -> Result<(), ScriptResultKind>
    where
        A: Fn() -> Option<ScriptResultKind>,
        B: Fn(Primitive) -> Option<ScriptResultKind>,
        C: Fn(StorageError) -> Option<ScriptResultKind>,
    {
        let _span = error_span!("kb_item", %key, kb_key).entered();
        let result = match self.storage.retrieve(key, Retrieve::KB(kb_key.to_string())) {
            Ok(mut x) => {
                let x = x.next();
                if let Some(x) = x {
                    match x {
                        Field::KB(kb) => {
                            trace!(value=?kb.value, "found");
                            result_some(kb.value)
                        }
                        x => {
                            trace!(field=?x, "found but it is not a KB item");
                            result_none()
                        }
                    }
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
                &key,
                k,
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
                &key,
                k,
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
                &key,
                k,
                || None,
                |_| Some(ScriptResultKind::ContainsExcludedKey(k.into())),
                |_| None,
            )
        };
        for k in &vt.excluded_keys {
            check_exclude_key(k)?
        }

        let check_port = |pt: Protocol, port: &str| {
            let kbk = generate_port_kb_key(pt, port);
            self.check_key(
                &key,
                &kbk,
                || Some(ScriptResultKind::MissingPort(pt, port.to_string())),
                |v| {
                    if v.into() {
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
    fn generate_key(&self) -> ContextKey {
        ContextKey::Scan(self.scan_id.clone(), Some(self.target.clone()))
    }

    async fn get_result_kind(&self, code: &str, register: Register) -> ScriptResultKind {
        if let Err(e) = self.check_keys(self.vt) {
            return e;
        }
        let mut target = Target::default();
        target.set_target(self.target.clone());

        let context = Context::new(
            self.generate_key(),
            target,
            self.storage.as_dispatcher(),
            self.storage.as_retriever(),
            self.loader,
            self.executor,
        );
        let mut results = Box::pin(CodeInterpreter::new(code, register, &context).stream());
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
        let kind = self.get_result_kind(&code, register).await;
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

pub(crate) fn generate_port_kb_key(protocol: crate::models::Protocol, port: &str) -> String {
    format!("Ports/{protocol}/{port}")
}
