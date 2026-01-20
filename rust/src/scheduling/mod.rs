// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module contains traits and implementations for scheduling a scan.
mod wave;

use std::{collections::HashMap, fmt::Display, io::Write, sync::Arc};

use crate::storage::{
    Retriever,
    error::StorageError,
    infisto::json::JsonStorage,
    inmemory::InMemoryStorage,
    items::nvt::{ACT, FileName, Oid},
    redis::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper},
};

use greenbone_scanner_framework::models::VTData;
use greenbone_scanner_framework::models::{Parameter, VT};
use thiserror::Error;

use wave::WaveExecutionPlan;

/// Error cases for VTFetcher
#[derive(Error, Debug, Clone)]
pub enum VTError {
    /// Underlying DB error.
    #[error("data-base error: {0}")]
    DB(#[from] StorageError),
    #[error("{0} misses required dependencies {1:?}")]
    /// Will be returned when Scheduler tries to schedule a VT with missing dependencies
    MissingDependencies(VTData, Vec<String>),
    #[error("invalid index ({0}) for Stage")]
    /// Not found
    NotFound(#[from] crate::nasl::syntax::LoadError),
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
/// The Stage to execute in
///
/// Only scripts within the the same Stage are allowed to be run concurrently
pub enum Stage {
    /// Discovery
    Discovery,
    /// NonEvasive
    NonEvasive,
    /// Evasive
    Exhausting,
    /// End
    End,
}

impl Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stage::Discovery => write!(f, "discovery"),
            Stage::NonEvasive => write!(f, "non_evasive"),
            Stage::Exhausting => write!(f, "exhausting"),
            Stage::End => write!(f, "end"),
        }
    }
}

impl Stage {
    fn from_vt(value: &VTData) -> Self {
        match value.category {
            ACT::Init | ACT::Scanner | ACT::Settings | ACT::GatherInfo => Self::Discovery,
            ACT::Attack | ACT::MixedAttack => Self::NonEvasive,
            ACT::DestructiveAttack | ACT::Denial | ACT::KillHost | ACT::Flood => Self::Exhausting,
            ACT::End => Self::End,
        }
    }

    fn from_stage_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Stage::Discovery),
            1 => Some(Stage::NonEvasive),
            2 => Some(Stage::Exhausting),
            3 => Some(Stage::End),
            _ => None,
        }
    }

    fn stage_index(&self) -> usize {
        match self {
            Stage::Discovery => 0,
            Stage::NonEvasive => 1,
            Stage::Exhausting => 2,
            Stage::End => 3,
        }
    }
}

pub trait SchedulerStorage:
    Retriever<Oid, Item = VTData> + Retriever<FileName, Item = VTData>
{
}

impl SchedulerStorage for InMemoryStorage {}
impl<T: Write + Send> SchedulerStorage for JsonStorage<T> {}
impl<T> SchedulerStorage for RedisStorage<T> where
    T: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Send
{
}
impl<T: SchedulerStorage + Send + Sync> SchedulerStorage for Arc<T> {}
impl<T: SchedulerStorage + ?Sized + Sync> SchedulerStorage for &T {}

pub struct Scheduler<S> {
    storage: S,
}

/// Contains the VTData and maybe parameter required to be executed
type RuntimeVT = (VTData, Option<Vec<Parameter>>);

/// Is the result of the Iterator if ExecutionPlaner
///
/// The reasoning to hide the structure behind an iterator of
/// (Stage, Vec<RuntimeVT>)
/// is to make it as inconvenient as possible to accidentally run scripts that
/// should not be run concurrently. Every item of the Vec of RuntimeVT can be run
/// concurrently. Each stage can be returned multiple times with a list of scripts
/// to be run. To allow tracing when a stage changed the stage information is given
/// as well.
pub type ConcurrentVT = (Stage, Vec<RuntimeVT>);

/// The categorization or ordering of VT may error
pub type ConcurrentVTResult = Result<ConcurrentVT, VTError>;

/// To make it as inconvenient as possible for the caller to accidentally execute scripts that should
/// not run concurrently in a concurrent fashion we return an iterator containing the stage as well
/// as scripts that can be run concurrently instead of returning the struct that contains the stage
/// data.
struct ExecutionPlanData {
    data: [WaveExecutionPlan; 4],
    idx: usize,
}

impl ExecutionPlanData {
    fn new(data: [WaveExecutionPlan; 4]) -> Self {
        Self { data, idx: 0 }
    }
}

impl Iterator for ExecutionPlanData {
    type Item = ConcurrentVTResult;

    fn next(&mut self) -> Option<Self::Item> {
        let stage = Stage::from_stage_index(self.idx)?;
        match self.data[self.idx].next() {
            None => {
                self.idx += 1;
                self.next()
            }
            Some(x) => match x {
                Ok(r) => Some(Ok((stage, r))),
                Err(e) => {
                    self.idx += 1;
                    Some(Err(e))
                }
            },
        }
    }
}

impl<S> Scheduler<S>
where
    S: SchedulerStorage,
{
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub fn execution_plan(
        &self,
        scan_vts: &[VT],
    ) -> Result<impl Iterator<Item = ConcurrentVTResult> + '_, VTError> {
        let mut results = core::array::from_fn(|_| WaveExecutionPlan::default());
        let mut unknown_dependencies = Vec::new();
        let mut known_dependencies = HashMap::new();
        let mut vts = vec![];

        // Collect all VT information
        for vt in scan_vts {
            if let Some(nvt) = self.storage.retrieve(&Oid(vt.oid.clone()))? {
                unknown_dependencies.extend(nvt.dependencies.clone());
                vts.push((nvt, Some(vt.parameters.clone())));
            } else {
                tracing::warn!(?vt.oid, "not found");
            }
        }

        while let Some(vt_name) = unknown_dependencies.pop() {
            if known_dependencies.contains_key(&vt_name) {
                continue;
            }
            if let Some(nvt) = self.storage.retrieve(&FileName(vt_name))? {
                unknown_dependencies.extend(nvt.dependencies.clone());
                known_dependencies.insert(nvt.filename.clone(), nvt);
            }
        }

        for (nvt, param) in vts.into_iter() {
            let stage = Stage::from_vt(&nvt);
            tracing::trace!(?stage, oid = nvt.oid, "adding");
            results[stage.stage_index()].append_vt((nvt, param), &known_dependencies)?;
        }

        Ok(ExecutionPlanData::new(results))
    }
}

#[cfg(test)]
mod tests {
    use greenbone_scanner_framework::models::VT;

    use crate::scanner::Scan;
    use crate::scheduling::Scheduler;
    use crate::scheduling::Stage;
    use crate::storage::Dispatcher;
    use crate::storage::inmemory::InMemoryStorage;
    use crate::storage::items::nvt::FileName;
    use greenbone_scanner_framework::models::VTData;

    #[test]
    #[tracing_test::traced_test]
    fn load_dependencies() {
        let feed = vec![
            VTData {
                oid: "0".to_string(),
                filename: "/0".to_string(),
                ..Default::default()
            },
            VTData {
                oid: "1".to_string(),
                filename: "/1".to_string(),
                dependencies: vec!["/0".to_string()],
                ..Default::default()
            },
            VTData {
                oid: "2".to_string(),
                filename: "/2".to_string(),
                dependencies: vec!["/1".to_string()],
                ..Default::default()
            },
        ];
        let storage = InMemoryStorage::new();
        feed.clone().into_iter().for_each(|nvt| {
            storage
                .dispatch(FileName(nvt.filename.clone()), nvt)
                .expect("should store");
        });

        let scan = Scan {
            vts: vec![VT {
                oid: "2".to_string(),
                parameters: vec![],
            }],
            ..Default::default()
        };
        let scheduler = Scheduler::new(&storage);
        let results: Vec<_> = scheduler
            .execution_plan(&scan.vts)
            .expect("no error expected")
            .filter_map(|x| x.ok())
            .collect();
        assert_eq!(
            vec![
                (Stage::End, vec![(feed[0].clone(), None)]),
                (Stage::End, vec![(feed[1].clone(), None)]),
                (Stage::End, vec![(feed[2].clone(), Some(vec![]))]),
            ],
            results
        )
    }
}
