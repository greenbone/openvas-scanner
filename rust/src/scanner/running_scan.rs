// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

use crate::models::{HostInfo, Phase, Status, scanner::Error};
use crate::nasl::utils::Executor;
use crate::{
    scanner::scan_runner::ScanRunner,
    scheduling::{ExecutionPlan, ExecutionPlaner, VTError},
};
use futures::StreamExt;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{debug, trace, warn};

use super::{ScannerStack, scan::Scan};

/// Takes care of running a single scan to completion.
/// Also provides methods for stopping the scan and
/// reading its status.
pub struct RunningScan<S: ScannerStack> {
    scan: Scan,
    storage: Arc<S::Storage>,
    loader: Arc<S::Loader>,
    function_executor: Arc<Executor>,
    keep_running: Arc<AtomicBool>,
    status: Arc<RwLock<Status>>,
}

pub(super) fn current_time_in_seconds(name: &'static str) -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(x) => x.as_secs(),
        Err(e) => {
            warn!(error=?e, name, "unable to get system time, setting defaulting to 0");
            0
        }
    }
}

impl<S: ScannerStack> RunningScan<S> {
    pub fn start<Sch: ExecutionPlan + 'static>(
        scan: Scan,
        storage: Arc<S::Storage>,
        loader: Arc<S::Loader>,
        function_executor: Arc<Executor>,
    ) -> RunningScanHandle
    where
        S: 'static,
    {
        let keep_running: Arc<AtomicBool> = Arc::new(true.into());
        let status = Arc::new(RwLock::new(Status {
            ..Default::default()
        }));
        RunningScanHandle {
            handle: tokio::spawn(
                Self {
                    scan,
                    storage,
                    loader,
                    function_executor,
                    keep_running: keep_running.clone(),
                    status: status.clone(),
                }
                // TODO run per target
                .run::<Sch>(),
            ),
            keep_running,
            status,
        }
    }

    async fn run<T>(self) -> Result<(), Error>
    where
        T: ExecutionPlan,
    {
        let runner = self.make_runner::<T>()?;
        self.update_status_at_beginning_of_run(runner.host_info())
            .await;
        let end_phase = self.run_to_completion(runner).await;

        self.update_status_at_end_of_run(end_phase).await;
        Ok(())
    }

    fn make_runner<'a, T>(&'a self) -> Result<ScanRunner<'a, S>, Error>
    where
        T: ExecutionPlan + 'a,
    {
        // TODO: This will become unnecessary once we merge crates
        // and can simply implement From<VTError> on scanner::Error;
        let make_scheduling_error = |e: VTError| Error::SchedulingError {
            id: self.scan.scan_id.to_string(),
            reason: e.to_string(),
        };
        let schedule = self
            .storage
            .execution_plan::<T>(&self.scan.vts)
            .map_err(make_scheduling_error)?;
        ScanRunner::new(
            &*self.storage,
            &*self.loader,
            &self.function_executor,
            schedule,
            &self.scan,
        )
        .map_err(make_scheduling_error)
    }

    async fn run_to_completion(&self, runner: ScanRunner<'_, S>) -> Phase {
        let mut end_phase = Phase::Succeeded;
        let mut stream = Box::pin(runner.stream());
        while let Some(it) = stream.next().await {
            match it {
                Ok(result) => {
                    trace!(target = result.target, targets=?self.scan.targets);
                    let mut status = self.status.write().await;
                    if let Some(host_info) = status.host_info.as_mut() {
                        host_info.register_finished_script(&result.target);
                    }
                    debug!(result=?result, "script finished");

                    if !result.has_succeeded() {
                        end_phase = Phase::Failed;
                    }
                }
                Err(x) => {
                    warn!(error=?x, "unrecoverable error, aborting whole run");
                    end_phase = Phase::Failed;
                }
            }
            if !self.keep_running.load(Ordering::SeqCst) {
                end_phase = Phase::Stopped;
                break;
            }
        }
        end_phase
    }

    async fn update_status_at_beginning_of_run(&self, host_info: HostInfo) {
        let mut status = self.status.write().await;
        status.status = Phase::Running;
        status.start_time = current_time_in_seconds("start_time").into();
        status.host_info = Some(host_info);
    }

    async fn update_status_at_end_of_run(&self, end_phase: Phase) {
        let mut status = self.status.write().await;
        status.status = end_phase;
        status.end_time = current_time_in_seconds("end_time").into();

        if let Some(host_info) = status.host_info.as_mut() {
            host_info.finish();
        }
    }
}

/// A handle to a `RunningScan`. Can be used to obtain the status of
/// the scan and to stop it.
pub struct RunningScanHandle {
    handle: JoinHandle<Result<(), Error>>,
    keep_running: Arc<AtomicBool>,
    status: Arc<RwLock<Status>>,
}

impl RunningScanHandle {
    pub fn stop(&self) {
        self.keep_running.store(false, Ordering::SeqCst);
        self.handle.abort();
    }

    pub async fn status(&self) -> Status {
        self.status.read().await.clone()
    }
}
