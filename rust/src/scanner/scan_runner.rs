// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::Loader;
use crate::nasl::utils::Executor;
use crate::nasl::utils::scan_ctx::{ContextStorage, NotusCtx, Target};
use futures::{Stream, stream};
use greenbone_scanner_framework::models::HostInfo;

use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, VTError};

use super::Scan;
use super::error::{ExecuteError, ScriptResult};
use super::vt_runner::VTRunner;

#[derive(Default, Debug, Clone, Copy)]
struct Position {
    host: usize,
    stage: usize,
    vt: usize,
}

/// Provides an iterator over all hosts, stages and vts within the stage
fn all_positions(hosts: Vec<Target>, vts: Vec<ConcurrentVT>) -> impl Iterator<Item = Position> {
    hosts.into_iter().enumerate().flat_map(move |(host, _)| {
        let vts = vts.clone();
        vts.into_iter()
            .enumerate()
            .flat_map(move |(stage, (_, vts))| {
                vts.into_iter()
                    .enumerate()
                    .map(move |(vt, _)| Position { host, stage, vt })
            })
    })
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
        let data =
            all_positions(self.scan.targets.clone(), self.concurrent_vts.clone()).map(move |pos| {
                let (stage, vts) = &self.concurrent_vts[pos.stage];
                let (vt, param) = &vts[pos.vt];
                let host = &self.scan.targets[pos.host];
                let ports = &self.scan.ports;
                (
                    *stage,
                    vt.clone(),
                    param.clone(),
                    host.clone(),
                    ports.clone(),
                    self.scan.scan_id.clone(),
                    self.notus.clone(),
                )
            });
        // The usage of unfold here will prevent any real asynchronous running of VTs
        // and automatically guarantee that we stick to the scheduling requirements.
        // If this is changed, make sure to uphold the scheduling requirements in the
        // new implementation.
        stream::unfold(data, move |mut data| async move {
            match data.next() {
                Some((stage, vt, param, host, ports, scan_id, notus)) => {
                    let result = VTRunner::<S>::run(
                        self.storage,
                        self.loader,
                        self.executor,
                        &host,
                        &ports,
                        &vt,
                        stage,
                        param.as_ref(),
                        scan_id,
                        &self.scan.scan_preferences,
                        &self.scan.alive_test_methods,
                        &notus,
                    )
                    .await;
                    Some((result, data))
                }
                _ => None,
            }
        })
    }
}
