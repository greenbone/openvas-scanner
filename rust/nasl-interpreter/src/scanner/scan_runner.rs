// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_syntax::{Loader, NaslValue};
use storage::types::Primitive;
use storage::{ContextKey, Retriever, Storage};

use crate::scanner::scan_interpreter::generate_port_kb_key;
use crate::scanner::ScannerStack;
use crate::scheduling::ConcurrentVT;

use super::error::{ExecuteError, ScriptResult, ScriptResultKind};

pub struct ScanRunner<'a, T, S: ScannerStack> {
    schedule: T,
    scan: &'a models::Scan,

    /// Default Retriever
    storage: &'a S::Storage,
    /// Default Loader
    loader: &'a S::Loader,
    executor: &'a S::Executor,
    /// Is used to remember which host we currently are executing. The host name will get through
    /// the stored scan reference.
    current_host: usize,
    /// The first value is the stage and the second the vt idx and is used in combincation with
    /// current_host
    ///
    /// This is necessary after the first host. Internally we use schedule and iterate over it,
    /// when there is no error then we store it within concurrent vts. After the first host is done
    /// we cached all schedule results and switch to the next host. To not have to reschedule we
    /// keep track of the position
    current_host_concurrent_vt_idx: (usize, usize),
    /// We cache the results of the scheduler
    concurrent_vts: Vec<ConcurrentVT>,
}

impl<'a, T, S: ScannerStack> ScanRunner<'a, T, S>
where
    T: Iterator<Item = crate::scheduling::ConcurrentVTResult> + 'a,
{
    pub fn new(
        scan: &'a models::Scan,
        storage: &'a S::Storage,
        loader: &'a S::Loader,
        executor: &'a S::Executor,
        schedule: T,
    ) -> Self {
        Self {
            schedule,
            scan,
            storage,
            loader,
            executor,
            concurrent_vts: vec![],
            current_host: 0,
            current_host_concurrent_vt_idx: (0, 0),
        }
    }

    fn parameter(
        &mut self,
        parameter: &models::Parameter,
        _register: &mut crate::Register,
    ) -> Result<(), ExecuteError> {
        // TODO: implement
        Err(ExecuteError::Parameter(parameter.clone()))
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
        let target = &self.scan.target.hosts[self.current_host].to_string();
        let scan_id = &self.scan.scan_id;
        ContextKey::Scan(scan_id.clone(), Some(target.clone()))
    }

    fn execute(
        &mut self,
        stage: crate::scheduling::Stage,
        vt: storage::item::Nvt,
        param: Option<Vec<models::Parameter>>,
    ) -> Result<ScriptResult, ExecuteError> {
        let code = self.loader.load(&vt.filename)?;
        let target = self.scan.target.hosts[self.current_host].to_string();
        let mut register = crate::Register::default();
        if let Some(params) = param {
            for p in params.iter() {
                self.parameter(p, &mut register)?;
            }
        }

        let _span = tracing::span!(
            tracing::Level::WARN,
            "executing",
            filename = &vt.filename,
            oid = &vt.oid,
            %stage,
            target,
        )
        .entered();

        // currently scans are limited to the target as well as the id.
        tracing::debug!("running");
        let kind = {
            match self.check_keys(&vt) {
                Err(e) => e,
                Ok(()) => {
                    let context = crate::Context::new(
                        self.generate_key(),
                        target.clone(),
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
            oid: vt.oid,
            filename: vt.filename,
            stage,
            kind,
            target,
        })
    }

    /// Checks if current current_host_concurrent_vt_idx as well as current_host are valid and may
    /// adapt them. Returns None when there are no hosts left.
    fn sanitize_indeces(&mut self) -> Option<Result<(usize, (usize, usize)), ExecuteError>> {
        let (mut si, mut vi) = self.current_host_concurrent_vt_idx;
        let mut hi = self.current_host;
        if self.current_host == 0 {
            // we cache all staging steps so that we can iterator through all vts per hosts.
            // this is easier to handle for the callter as they can
            match self.schedule.next() {
                Some(next) => {
                    match next {
                        Ok(next) => {
                            self.concurrent_vts.push(next);
                        }
                        Err(e) => {
                            // Note: if the caller ignores the error and continues then the
                            // VT will be skipped and may result in unpredictable behaviour
                            // in the following runs. An alternative approach would be to
                            // go to the next host. That way the run would stop at the
                            // fauly scheduling for each run instead of trying to continue.
                            return Some(Err(e.into()));
                        }
                    }
                }
                None => {
                    // finished first run
                }
            }
        }
        let new_host = si >= self.concurrent_vts.len()
            || (vi >= self.concurrent_vts[si].1.len() && si + 1 >= self.concurrent_vts.len());
        if new_host {
            if let Err(e) = self.storage.scan_finished(&self.generate_key()) {
                return Some(Err(e.into()));
            }
            si = 0;
            vi = 0;
            hi += 1;
        } else if vi >= self.concurrent_vts[si].1.len() {
            // new_stage
            si += 1;
            vi = 0;
        }

        if hi < self.scan.target.hosts.len() {
            self.current_host = hi;
            self.current_host_concurrent_vt_idx = (si, vi);
            Some(Ok((hi, (si, vi))))
        } else {
            None
        }
    }
}

impl<'a, T, S: ScannerStack> Iterator for ScanRunner<'a, T, S>
where
    T: Iterator<Item = crate::scheduling::ConcurrentVTResult> + 'a,
{
    type Item = Result<ScriptResult, ExecuteError>;

    fn next(&mut self) -> Option<Self::Item> {
        let (_, (si, vi)) = match self.sanitize_indeces()? {
            Ok(x) => x,
            Err(e) => {
                self.current_host_concurrent_vt_idx = (
                    self.current_host_concurrent_vt_idx.0,
                    self.current_host_concurrent_vt_idx.1 + 1,
                );
                return Some(Err(e));
            }
        };

        let (stage, vts) = &self.concurrent_vts[si];
        let (vt, param) = &vts[vi];

        self.current_host_concurrent_vt_idx = (si, vi + 1);

        Some(self.execute(stage.clone(), vt.clone(), param.clone()))
    }
}
