use models::{Host, Parameter, ScanId};
use nasl_builtin_utils::Register;
use nasl_syntax::{Loader, NaslValue};
use storage::{item::Nvt, types::Primitive, ContextKey, Retriever, Storage};

use crate::{scheduling::Stage, ExecuteError};

use super::{
    error::{ScriptResult, ScriptResultKind},
    ScannerStack,
};

/// TODO: doc
pub struct VTRunner<'a, S: ScannerStack> {
    storage: &'a S::Storage,
    loader: &'a S::Loader,
    executor: &'a S::Executor,

    target: &'a Host,
    vt: &'a Nvt,
    stage: Stage,
    param: Option<&'a Vec<Parameter>>,
    scan_id: &'a ScanId,
}

impl<'a, Stack: ScannerStack> VTRunner<'a, Stack> {
    pub fn run(
        storage: &'a Stack::Storage,
        loader: &'a Stack::Loader,
        executor: &'a Stack::Executor,
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
        s.execute()
    }

    fn parameter(
        &self,
        parameter: &models::Parameter,
        _register: &mut crate::Register,
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
        key: &storage::ContextKey,
        kb_key: &str,
        result_none: A,
        result_some: B,
        result_err: C,
    ) -> Result<(), ScriptResultKind>
    where
        A: Fn() -> Option<ScriptResultKind>,
        B: Fn(Primitive) -> Option<ScriptResultKind>,
        C: Fn(storage::StorageError) -> Option<ScriptResultKind>,
    {
        let _span = tracing::error_span!("kb_item", %key, kb_key).entered();
        let result = match self
            .storage
            .retrieve(key, storage::Retrieve::KB(kb_key.to_string()))
        {
            Ok(mut x) => {
                let x = x.next();
                if let Some(x) = x {
                    match x {
                        storage::Field::KB(kb) => {
                            tracing::trace!(value=?kb.value, "found");
                            result_some(kb.value)
                        }
                        x => {
                            tracing::trace!(field=?x, "found but it is not a KB item");
                            result_none()
                        }
                    }
                } else {
                    tracing::trace!("not found");
                    result_none()
                }
            }
            Err(e) => {
                tracing::warn!(error=%e, "storage error");
                result_err(e)
            }
        };
        match result {
            None => Ok(()),
            Some(x) => Err(x),
        }
    }

    fn check_keys(&self, vt: &storage::item::Nvt) -> Result<(), ScriptResultKind> {
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

        use models::Protocol;
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

    fn execute(mut self) -> Result<ScriptResult, ExecuteError> {
        let code = self.loader.load(&self.vt.filename)?;
        let mut register = crate::Register::default();
        self.set_parameters(&mut register)?;

        let _span = tracing::span!(
            tracing::Level::WARN,
            "executing",
            filename = &self.vt.filename,
            oid = &self.vt.oid,
            %self.stage,
            self.target,
        )
        .entered();

        // currently scans are limited to the target as well as the id.
        tracing::debug!("running");
        let kind = {
            match self.check_keys(&self.vt) {
                Err(e) => e,
                Ok(()) => {
                    let context = crate::Context::new(
                        self.generate_key(),
                        self.target.clone(),
                        self.storage.as_dispatcher(),
                        self.storage.as_retriever(),
                        self.loader,
                        self.executor,
                    );
                    let mut interpret = crate::CodeInterpreter::new(&code, register, &context);

                    interpret
                        .find_map(|r| match r {
                            Ok(NaslValue::Exit(x)) => Some(ScriptResultKind::ReturnCode(x)),
                            Err(e) => Some(ScriptResultKind::Error(e.clone())),
                            Ok(x) => {
                                tracing::trace!(statement_result=?x);
                                None
                            }
                        })
                        .unwrap_or_else(|| ScriptResultKind::ReturnCode(0))
                }
            }
        };
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

pub(crate) fn generate_port_kb_key(protocol: models::Protocol, port: &str) -> String {
    format!("Ports/{protocol}/{port}")
}
