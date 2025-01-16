// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::SystemTime,
};

use crate::models::{scanner::Error, HostInfo, Phase, Scan, Status};
use crate::nasl::utils::Executor;
use crate::{
    scanner::scan_runner::ScanRunner,
    scheduling::{ExecutionPlan, ExecutionPlaner, VTError},
};
use futures::StreamExt;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{debug, trace, warn};

use super::ScannerStack;

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

fn current_time_in_seconds(name: &'static str) -> u64 {
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
            .execution_plan::<T>(&self.scan)
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
                    trace!(target = result.target, targets=?self.scan.target.hosts);
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::models::Phase;
    use crate::models::{
        scanner::{ScanResultFetcher, ScanResults, ScanStarter},
        Scan,
    };
    use crate::storage::{item::Nvt, DefaultDispatcher};
    use tracing_test::traced_test;

    use crate::scanner::{
        scan_runner::tests::{setup, setup_success, GenerateScript},
        Scanner,
    };

    type TestStack = (DefaultDispatcher, fn(&str) -> String);

    fn make_scanner_and_scan_success() -> (Scanner<TestStack>, Scan) {
        let ((storage, loader, executor), scan) = setup_success();
        (Scanner::new(storage, loader, executor), scan)
    }

    fn make_scanner_and_scan(scripts: &[(String, Nvt)]) -> (Scanner<TestStack>, Scan) {
        let ((storage, loader, executor), scan) = setup(scripts);
        (Scanner::new(storage, loader, executor), scan)
    }

    /// Blocks until given id is in given phase or panics after 1 second
    async fn wait_for_status(scanner: Scanner<TestStack>, id: &str, phase: Phase) -> ScanResults {
        let start = super::current_time_in_seconds("test");
        assert!(start > 0);
        loop {
            let current = super::current_time_in_seconds("loop test");
            assert!(
                current > 0,
                "it was not possible to get the system time in seconds"
            );
            assert!(current - start < 1, "time for finishing scan is up.");
            // we need the sloep to not instantly read lock running and preventing write access
            tokio::time::sleep(Duration::from_nanos(100)).await;
            let scan_results = scanner
                .fetch_results(id.to_string())
                .await
                .expect("no error when fetching results");
            tracing::debug!(status=%scan_results.status.status);
            if scan_results.status.status == phase {
                return scan_results;
            }
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn start_scan_failure() {
        let failures = [GenerateScript {
            id: "0".into(),
            rc: 1,
            ..Default::default()
        }
        .generate()];

        let (scanner, scan) = make_scanner_and_scan(&failures);

        let id = scan.scan_id.clone();
        let res = scanner.start_scan(scan).await;
        assert!(res.is_ok());
        let scan_results = wait_for_status(scanner, &id, Phase::Succeeded).await;

        assert!(
            scan_results.status.start_time.is_some(),
            "expect start time to be set when scan starts"
        );
        assert!(
            scan_results.status.end_time.is_some(),
            "expect end time to be set when scan finished"
        );
        assert!(
            scan_results.status.host_info.is_some(),
            "host_info should be set"
        );
        let host_info = scan_results.status.host_info.unwrap();
        assert_eq!(host_info.finished(), 1);
        assert_eq!(host_info.queued(), 0);
    }

    #[tokio::test]
    #[traced_test]
    async fn start_scan_success() {
        let (scanner, mut scan) = make_scanner_and_scan_success();
        scan.target.hosts.push("wald.fee".to_string());

        let id = scan.scan_id.clone();
        let res = scanner.start_scan(scan).await;
        assert!(res.is_ok());
        let scan_results = wait_for_status(scanner, &id, Phase::Succeeded).await;

        assert!(
            scan_results.status.start_time.is_some(),
            "expect start time to be set when scan starts"
        );
        assert!(
            scan_results.status.end_time.is_some(),
            "expect end time to be set when scan finished"
        );
        assert!(
            scan_results.status.host_info.is_some(),
            "host_info should be set"
        );
        let host_info = scan_results.status.host_info.unwrap();
        assert_eq!(host_info.finished(), 2);
        assert_eq!(host_info.queued(), 0);
    }
}
