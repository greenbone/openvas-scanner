// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::HostInfo;
use crate::nasl::utils::Executor;
use crate::nasl::utils::context::Target;
use futures::{Stream, stream};

use crate::scanner::ScannerStack;
use crate::scheduling::{ConcurrentVT, VTError};

use super::Scan;
use super::error::{ExecuteError, ScriptResult};
use super::scanner_stack::Schedule;
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
pub struct ScanRunner<'a, S: ScannerStack> {
    scan: &'a Scan,
    storage: &'a S::Storage,
    loader: &'a S::Loader,
    executor: &'a Executor,
    concurrent_vts: Vec<ConcurrentVT>,
}

impl<'a, Stack: ScannerStack> ScanRunner<'a, Stack> {
    pub fn new<Sched>(
        storage: &'a Stack::Storage,
        loader: &'a Stack::Loader,
        executor: &'a Executor,
        schedule: Sched,
        scan: &'a Scan,
    ) -> Result<Self, VTError>
    where
        Sched: Schedule + 'a,
    {
        let concurrent_vts = schedule.cache()?;
        Ok(Self {
            scan,
            storage,
            loader,
            executor,
            concurrent_vts,
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
                (
                    *stage,
                    vt.clone(),
                    param.clone(),
                    host.clone(),
                    self.scan.scan_id.clone(),
                )
            });
        // The usage of unfold here will prevent any real asynchronous running of VTs
        // and automatically guarantee that we stick to the scheduling requirements.
        // If this is changed, make sure to uphold the scheduling requirements in the
        // new implementation.
        stream::unfold(data, move |mut data| async move {
            match data.next() {
                Some((stage, vt, param, host, scan_id)) => {
                    let result = VTRunner::<Stack>::run(
                        self.storage,
                        self.loader,
                        self.executor,
                        &host,
                        &vt,
                        stage,
                        param.as_ref(),
                        scan_id,
                        &self.scan.scan_preferences,
                    )
                    .await;
                    Some((result, data))
                }
                _ => None,
            }
        })
    }
}
