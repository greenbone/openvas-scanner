// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

use crate::models::{Host, HostInfo, Phase, Status};
use crate::nasl::{
    syntax::Loader,
    utils::{Executor, ctx::CtxTarget},
};
use crate::scanner::Error;
use crate::{alive_test::Scanner as BoreasScanner, nasl::utils::ctx::TargetId};
use crate::{
    nasl::{
        ScanCtx,
        utils::ctx::{ContextStorage, NotusCtx},
    },
    storage::ScanID,
};
use crate::{
    scanner::scan_runner::ScanRunner,
    scheduling::{Scheduler, SchedulerStorage, VTError},
};
use tokio::sync::mpsc::{self, Receiver};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{debug, trace, warn};

use super::error::{ExecuteError, ScriptResult};
use super::scan::Scan;

/// Takes care of running a single scan to completion.
/// Also provides methods for stopping the scan and
/// reading its status.
pub struct RunningScan<S> {
    scan: Scan,
    storage: Arc<S>,
    loader: Arc<Loader>,
    function_executor: Arc<Executor>,
    keep_running: Arc<AtomicBool>,
    status: Arc<RwLock<Status>>,
    notus: Option<NotusCtx>,
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

impl<S> RunningScan<S>
where
    S: ContextStorage + SchedulerStorage + Send + Sync + Clone + 'static,
{
    pub fn start(
        scan: Scan,
        storage: Arc<S>,
        loader: Arc<Loader>,
        function_executor: Arc<Executor>,
        notus: Option<NotusCtx>,
    ) -> RunningScanHandle {
        let keep_running: Arc<AtomicBool> = Arc::new(true.into());
        let status = Arc::new(RwLock::new(Status {
            ..Default::default()
        }));

        let host_by_ip: HashMap<String, TargetId> = scan
            .targets
            .enumerate()
            .map(|(i, t)| (t.ip_addr().to_string(), i))
            .collect();
        let host_set: HashSet<Host> = host_by_ip.keys().cloned().collect();
        let methods = scan.alive_test_methods.clone();
        let capacity = host_by_ip.len().max(1);

        // This channel is for sending a target to the running scan.
        let (tx_target, rx_target) = mpsc::channel::<TargetId>(capacity);
        // This channel receives alive host from the alive test scanner
        let (tx_host, mut rx_host) = mpsc::channel::<Host>(capacity);

        // Resolves every host reported alive to its `Target` and forwards
        // it to the running scan so it can start scanning it right away.
        tokio::spawn(async move {
            while let Some(host) = rx_host.recv().await {
                if let Some(target) = host_by_ip.get(&host)
                    && tx_target.send(*target).await.is_err()
                {
                    break;
                }
            }
            // Dropping `tx_target` here closes the channel, signalling to
            // the running scan that no further hosts will arrive.
        });

        let status_for_alive = status.clone();
        tokio::spawn(async move {
            let alive_scanner = BoreasScanner::new(host_set.clone(), methods, None);
            let alive = match alive_scanner.run_alive_test_streaming(Some(tx_host)).await {
                Ok(alive) => alive,
                Err(e) => {
                    warn!(error=?e, "alive test failed; no hosts will be scanned");
                    return;
                }
            };
            let dead: Vec<String> = host_set.difference(&alive).cloned().collect();
            if !dead.is_empty() {
                mark_hosts_dead_when_available(&status_for_alive, &dead).await;
            }
        });

        RunningScanHandle {
            handle: tokio::spawn(
                Self {
                    scan,
                    storage,
                    loader,
                    function_executor,
                    keep_running: keep_running.clone(),
                    status: status.clone(),
                    notus,
                }
                .run(rx_target),
            ),
            keep_running,
            status,
        }
    }

    async fn run(self, host_feed: Receiver<TargetId>) -> Result<(), Error> {
        let targets = self
            .scan
            .targets
            .iter()
            .map(|target| CtxTarget::new(target.clone(), self.scan.ports.clone()))
            .collect();
        let scan_ctx = Arc::new(ScanCtx::new(
            ScanID(self.scan.scan_id.clone()),
            targets,
            self.storage.clone(),
            self.loader.clone(),
            self.function_executor.clone(),
            self.scan.scan_preferences.clone(),
            self.scan.alive_test_methods.clone(),
            self.notus.clone(),
        ));
        let runner = match self.make_runner(host_feed, scan_ctx).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("{}", e);
                return Err(e);
            }
        };
        self.update_status_at_beginning_of_run(runner.host_info())
            .await;
        let end_phase = self.run_to_completion(runner).await;
        self.update_status_at_end_of_run(end_phase).await;
        Ok(())
    }

    async fn make_runner(
        &self,
        host_feed: Receiver<TargetId>,
        scan_ctx: Arc<ScanCtx>,
    ) -> Result<ScanRunner, Error> {
        // TODO: This will become unnecessary once we merge crates
        // and can simply implement From<VTError> on scanner::Error;
        let make_scheduling_error = |e: VTError| Error::SchedulingError {
            id: self.scan.scan_id.to_string(),
            reason: e.to_string(),
        };
        let scheduler = Scheduler::new(self.storage.clone());
        let schedule: Vec<_> = scheduler
            .execution_plan(&self.scan.vts)
            .await
            .map_err(make_scheduling_error)?
            .collect::<Result<_, _>>()
            .map_err(make_scheduling_error)?;

        ScanRunner::new(schedule.into_iter().map(Ok), host_feed, scan_ctx)
            .map_err(make_scheduling_error)
    }

    async fn run_to_completion(&self, runner: ScanRunner) -> Phase {
        // TODO: improve logic here. Replace Phase with a better type to
        // represent the possible state.
        let end_phase = Arc::new(std::sync::Mutex::new(Phase::Succeeded));
        let (status, phase) = (self.status.clone(), end_phase.clone());
        // One task per host; each result updates the shared status.
        let panicked = runner
            .run(self.keep_running.clone(), move |res| {
                handle_result(status.clone(), phase.clone(), res)
            })
            .await;

        if !self.keep_running.load(Ordering::SeqCst) {
            return Phase::Stopped;
        }
        if panicked > 0 {
            return Phase::Failed;
        }
        end_phase.lock().map(|p| p.clone()).unwrap_or(Phase::Failed)
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

/// Records the result of a single VT in `status` and updates `end_phase`
/// if the result means that the scan failed.
async fn handle_result(
    status: Arc<RwLock<Status>>,
    end_phase: Arc<std::sync::Mutex<Phase>>,
    result: Result<ScriptResult, ExecuteError>,
) {
    let fail = || {
        if let Ok(mut phase) = end_phase.lock() {
            *phase = Phase::Failed;
        }
    };
    match result {
        Ok(result) => {
            trace!(target = result.target);
            let mut status = status.write().await;
            if let Some(host_info) = status.host_info.as_mut() {
                host_info.register_finished_script(&result.target);
            }
            debug!(result=?result, "script finished");

            if result.kind.is_fatal() {
                fail();
            }
        }
        Err(x) => {
            warn!(error=?x, "unrecoverable error, aborting whole run");
            fail();
        }
    }
}

/// Marks the given hosts as dead in `status`, once its `host_info` has
/// been populated by [`RunningScan::update_status_at_beginning_of_run`].
/// The alive test and the scheduling of the scan (which determines when
/// `host_info` becomes available) run concurrently, so this waits (with
/// a bounded number of retries) until `host_info` is set.
//TODO: if possible initialize host_info instead of wait.
async fn mark_hosts_dead_when_available(status: &Arc<RwLock<Status>>, dead_hosts: &[String]) {
    const MAX_ATTEMPTS: usize = 200;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);

    for _ in 0..MAX_ATTEMPTS {
        {
            let mut status = status.write().await;
            if let Some(host_info) = status.host_info.as_mut() {
                host_info.mark_hosts_dead(dead_hosts.iter().map(String::as_str));
                return;
            }
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
    warn!("scan status was never initialized; unable to mark dead hosts");
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
