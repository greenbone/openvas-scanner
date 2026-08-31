// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::VecDeque;
use std::sync::Arc;

use crate::models::{self, HostInfo, ResultType};
use crate::nasl::syntax::Loader;
use crate::nasl::utils::Executor;
use crate::nasl::utils::scan_ctx::{ContextStorage, NotusCtx, Target};
use crate::storage::ScanID;
use chrono::Utc;
use futures::{Stream, stream};
use tokio::sync::mpsc::Receiver;
use tracing::warn;

use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, VTError};

use super::Scan;
use super::error::{ExecuteError, ScriptResult};
use super::vt_runner::VTRunner;

#[derive(Debug, Clone)]
struct Position {
    host: Target,
    stage: usize,
    vt: usize,
}

/// Given the currently known `vts` schedule, enqueues all `(stage, vt)`
/// positions that need to be run for `host`.
fn enqueue_host(queue: &mut VecDeque<Position>, host: &Target, vts: &[ConcurrentVT]) {
    for (stage, (_, stage_vts)) in vts.iter().enumerate() {
        for vt in 0..stage_vts.len() {
            queue.push_back(Position {
                host: host.clone(),
                stage,
                vt,
            });
        }
    }
}

/// Runs a single scan by executing all the VTs within a given schedule.
/// This does not provide any control over the scan but merely executes the
/// necessary instructions. In order to have control over the scan (such as
/// starting and stopping it), use `RunningScan` instead.
pub struct ScanRunner<'a, S> {
    scan: &'a Scan,
    storage: &'a S,
    loader: &'a Loader,
    executor: &'a Executor,
    concurrent_vts: Arc<Vec<ConcurrentVT>>,
    notus: &'a Option<NotusCtx>,
    host_feed: Receiver<Target>,
}

impl<'a, S> ScanRunner<'a, S>
where
    S: ContextStorage,
{
    pub fn new<Sched>(
        storage: &'a S,
        loader: &'a Loader,
        executor: &'a Executor,
        schedule: Sched,
        scan: &'a Scan,
        notus: &'a Option<NotusCtx>,
        host_feed: Receiver<Target>,
    ) -> Result<Self, VTError>
    where
        Sched: Iterator<Item = ConcurrentVTResult> + 'a,
    {
        let concurrent_vts = Arc::new(schedule.collect::<Result<Vec<_>, _>>()?);
        Ok(Self {
            scan,
            storage,
            loader,
            executor,
            concurrent_vts,
            notus,
            host_feed,
        })
    }

    pub fn host_info(&self) -> HostInfo {
        let num_vts: usize = self.concurrent_vts.iter().map(|(_, vts)| vts.len()).sum();
        HostInfo::from_hosts_and_num_vts(
            self.scan
                .targets
                .iter()
                .map(|target| target.original_target_str()),
            num_vts,
        )
    }

    pub fn stream(self) -> impl Stream<Item = Result<ScriptResult, ExecuteError>> + 'a {
        let ScanRunner {
            scan,
            storage,
            loader,
            executor,
            concurrent_vts,
            notus,
            host_feed,
        } = self;
        let last_host: Option<Target> = None;
        let state = (host_feed, VecDeque::<Position>::new(), last_host);
        // The usage of unfold here will prevent any real asynchronous running of VTs
        // and automatically guarantee that we stick to the scheduling requirements.
        // If this is changed, make sure to uphold the scheduling requirements in the
        // new implementation.

        stream::unfold(state, move |(mut host_feed, mut queue, mut last_host)| {
            let concurrent_vts = concurrent_vts.clone();
            async move {
                loop {
                    if queue.is_empty() {
                        if let Some(host) = host_feed.recv().await {
                            enqueue_host(&mut queue, &host, &concurrent_vts);
                        } else {
                            return None;
                        }
                    }

                    if let Some(pos) = queue.pop_front() {
                        let is_host_start = last_host != Some(pos.host.clone());
                        last_host = Some(pos.host.clone());
                        if is_host_start {
                            let result = models::Result {
                                id: 0,
                                r_type: ResultType::HostStart,
                                ip_address: Some(pos.host.original_target_str().to_string()),
                                hostname: None,
                                oid: None,
                                port: None,
                                protocol: None,
                                message: Some(Utc::now().to_string()),
                                detail: None,
                            };
                            if let Err(e) = self
                                .storage
                                .retry_dispatch(ScanID(scan.scan_id.clone()), result, 5)
                                .await
                            {
                                warn!(
                                    error=?e,
                                    host = pos.host.original_target_str(),
                                    "unable to dispatch HostStart result"
                                );
                            }
                        }
                        let (stage, vts) = &concurrent_vts[pos.stage];
                        let (vt, param) = &vts[pos.vt];
                        let result = VTRunner::<S>::run(
                            storage,
                            loader,
                            executor,
                            &pos.host,
                            &scan.ports,
                            vt,
                            *stage,
                            param.as_ref(),
                            scan.scan_id.clone(),
                            &scan.scan_preferences,
                            &scan.alive_test_methods,
                            notus,
                        )
                        .await;
                        return Some((result, (host_feed, queue, last_host)));
                    }
                }
            }
        })
    }
}
