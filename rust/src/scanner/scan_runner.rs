// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::VecDeque;

use crate::models::HostInfo;
use crate::nasl::syntax::Loader;
use crate::nasl::utils::Executor;
use crate::nasl::utils::scan_ctx::{ContextStorage, NotusCtx, Target};
use futures::{Stream, stream};
use tokio::sync::mpsc::Receiver;

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
    concurrent_vts: Vec<ConcurrentVT>,
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
        let concurrent_vts = schedule.collect::<Result<Vec<_>, _>>()?;
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
        HostInfo::from_hosts_and_num_vts(
            self.scan
                .targets
                .iter()
                .map(|target| target.original_target_str()),
            self.concurrent_vts.len(),
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
        let state = (host_feed, VecDeque::<Position>::new());
        // The usage of unfold here will prevent any real asynchronous running of VTs
        // and automatically guarantee that we stick to the scheduling requirements.
        // If this is changed, make sure to uphold the scheduling requirements in the
        // new implementation.
        stream::unfold(state, move |(mut host_feed, mut queue)| {
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
                        return Some((result, (host_feed, queue)));
                    }
                }
            }
        })
    }
}
