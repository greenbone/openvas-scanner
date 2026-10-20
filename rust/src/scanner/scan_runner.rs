// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::models::HostInfo;
use crate::nasl::ScanCtx;
use crate::nasl::utils::ctx::TargetId;
use crate::nasl::utils::mtime::MtimeStatus;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, VTError};

use super::error::{ExecuteError, ScriptResult, ScriptResultKind};
use super::vt_runner::VTRunner;

const MAX_HOSTS_PREFERENCE: &str = "max_hosts";
pub const DEFAULT_MAX_HOSTS: usize = 15;

#[derive(Debug, Clone)]
struct Position {
    target: TargetId,
    stage: usize,
    vt: usize,
}

/// Given the currently known `vts` schedule, returns all `(stage, vt)`
/// positions that need to be run for `host`, in the order they have to be
/// executed.
fn host_positions(host: TargetId, vts: &[ConcurrentVT]) -> Vec<Position> {
    vts.iter()
        .enumerate()
        .flat_map(|(stage, (_, stage_vts))| {
            (0..stage_vts.len()).map(move |vt| Position {
                target: host,
                stage,
                vt,
            })
        })
        .collect()
}

async fn run_vt_checked(
    target: TargetId,
    vt: &crate::models::VTData,
    stage: crate::scheduling::Stage,
    param: Option<&Vec<crate::models::Parameter>>,
    scan_ctx: &ScanCtx,
) -> Result<ScriptResult, ExecuteError> {
    let failed = |msg: String| {
        Ok(ScriptResult {
            oid: vt.oid.clone(),
            filename: vt.filename.clone(),
            stage,
            kind: ScriptResultKind::MtimeCheckFailed(msg),
            target: scan_ctx.target_by_id(target).original_target_str().into(),
        })
    };
    match scan_ctx
        .storage()
        .check_mtime(Path::new(&vt.filename))
        .await
    {
        Ok(MtimeStatus::UpToDate) => VTRunner::run(target, vt, stage, param, scan_ctx).await,
        Ok(MtimeStatus::Modified {
            file,
            stored,
            current,
        }) => failed(format!(
            "The VT {file} has been modified since it has mtime {current} newer than the stored {stored}"
        )),
        Err(reason) => failed(reason),
    }
}

fn max_parallel_hosts(preference: Option<i64>) -> usize {
    match preference {
        Some(n) if n > 0 => usize::try_from(n).unwrap_or(DEFAULT_MAX_HOSTS),
        _ => DEFAULT_MAX_HOSTS,
    }
}

/// Runs a single scan by executing all the VTs within a given schedule.
/// This does not provide any control over the scan but merely executes the
/// necessary instructions. In order to have control over the scan (such as
/// starting and stopping it), use `RunningScan` instead.
pub struct ScanRunner {
    concurrent_vts: Arc<Vec<ConcurrentVT>>,
    host_feed: Receiver<TargetId>,
    scan_ctx: Arc<ScanCtx>,
    max_hosts: usize,
}

impl ScanRunner {
    pub fn new<Sched>(
        schedule: Sched,
        host_feed: Receiver<TargetId>,
        scan_ctx: Arc<ScanCtx>,
    ) -> Result<Self, VTError>
    where
        Sched: Iterator<Item = ConcurrentVTResult>,
    {
        let concurrent_vts = Arc::new(schedule.collect::<Result<Vec<_>, _>>()?);
        let max_hosts = max_parallel_hosts(
            scan_ctx
                .scan_preferences
                .get_preference_int(MAX_HOSTS_PREFERENCE),
        );
        Ok(Self {
            concurrent_vts,
            host_feed,
            scan_ctx,
            max_hosts,
        })
    }

    /// Overrides the number of hosts that are scanned in parallel.
    /// A value of 0 is treated as 1.
    pub fn with_max_hosts(mut self, max_hosts: usize) -> Self {
        self.max_hosts = max_hosts.max(1);
        self
    }

    pub fn host_info(&self) -> HostInfo {
        HostInfo::from_hosts_and_num_vts(
            self.scan_ctx
                .targets()
                .iter()
                .map(|target| target.original_target_str()),
            self.concurrent_vts.len(),
        )
    }

    /// Runs all VTs against all hosts received on the host feed, spawning
    /// one tokio task per host, with at most `max_hosts` host tasks alive at
    /// the same time. A task is spawned as soon as a host is reported alive
    /// and a slot is free.
    ///
    /// For each host the VTs run strictly in schedule order, so the
    /// scheduling requirements hold for every host. `on_result` is called,
    /// from the host's task, with the result of every VT; no ordering is
    /// guaranteed between results of different hosts. When `keep_running`
    /// becomes false no further VT or host is started; a VT that is
    /// already running is not interrupted. Dropping the returned future
    /// aborts the host tasks.
    ///
    /// Returns the number of host tasks that panicked.
    pub async fn run<F, Fut>(self, keep_running: Arc<AtomicBool>, on_result: F) -> usize
    where
        F: Fn(Result<ScriptResult, ExecuteError>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let ScanRunner {
            concurrent_vts,
            mut host_feed,
            scan_ctx,
            max_hosts,
        } = self;
        let on_result = Arc::new(on_result);
        let mut hosts = JoinSet::new();
        let mut panicked = 0;
        let mut count_panic = |res: Result<(), tokio::task::JoinError>| {
            if let Err(e) = res {
                warn!(error=?e, "host scan task failed");
                panicked += 1;
            }
        };

        while keep_running.load(Ordering::SeqCst) {
            // Wait for a free slot.
            while hosts.len() >= max_hosts {
                if let Some(res) = hosts.join_next().await {
                    count_panic(res);
                }
            }
            // Wait for the next alive host, but wake up regularly to notice
            // that the scan was stopped.
            let host =
                match tokio::time::timeout(Duration::from_millis(200), host_feed.recv()).await {
                    Ok(Some(host)) => host,
                    Ok(None) => break,
                    Err(_) => continue,
                };

            let concurrent_vts = concurrent_vts.clone();
            let scan_ctx = scan_ctx.clone();
            let on_result = on_result.clone();
            let keep_running = keep_running.clone();
            hosts.spawn(async move {
                for pos in host_positions(host, &concurrent_vts) {
                    if !keep_running.load(Ordering::SeqCst) {
                        break;
                    }
                    let (stage, vts) = &concurrent_vts[pos.stage];
                    let (vt, param) = &vts[pos.vt];
                    let result =
                        run_vt_checked(pos.target, vt, *stage, param.as_ref(), &scan_ctx).await;
                    on_result(result).await;
                }
            });
        }

        while let Some(res) = hosts.join_next().await {
            count_panic(res);
        }
        panicked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_hosts_uses_preference_when_valid() {
        assert_eq!(max_parallel_hosts(Some(4)), 4);
        assert_eq!(max_parallel_hosts(Some(1)), 1);
    }

    #[test]
    fn parallel_hosts_falls_back_to_default() {
        assert_eq!(max_parallel_hosts(None), DEFAULT_MAX_HOSTS);
        assert_eq!(max_parallel_hosts(Some(0)), DEFAULT_MAX_HOSTS);
        assert_eq!(max_parallel_hosts(Some(-3)), DEFAULT_MAX_HOSTS);
    }

    #[test]
    fn host_positions_keep_schedule_order() {
        use crate::nasl::utils::indexed_arena::ArenaIndex;
        use crate::scheduling::Stage;

        let vt = |name: &str| crate::models::VTData {
            oid: name.to_string(),
            filename: name.to_string(),
            ..Default::default()
        };
        let schedule: Vec<ConcurrentVT> = vec![
            (Stage::Discovery, vec![(vt("a"), None), (vt("b"), None)]),
            (Stage::NonEvasive, vec![(vt("c"), None)]),
        ];
        let positions = host_positions(TargetId::from_index(7), &schedule);
        let got: Vec<_> = positions
            .iter()
            .map(|p| (p.target.to_index(), p.stage, p.vt))
            .collect();
        assert_eq!(got, vec![(7, 0, 0), (7, 0, 1), (7, 1, 0)]);
    }
}
