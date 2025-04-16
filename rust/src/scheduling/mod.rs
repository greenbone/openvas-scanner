// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module contains traits and implementations for scheduling a scan.
mod wave;

use std::{collections::HashMap, fmt::Display, io::Write, sync::Arc};

use crate::{
    models::{Parameter, VT},
    storage::{
        Retriever,
        error::StorageError,
        infisto::json::JsonStorage,
        inmemory::InMemoryStorage,
        items::nvt::{ACT, FileName, Nvt, Oid},
        redis::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorage, RedisWrapper},
    },
};
use thiserror::Error;

pub use wave::WaveExecutionPlan;

/// Error cases for VTFetcher
#[derive(Error, Debug, Clone)]
pub enum VTError {
    /// Underlying DB error.
    #[error("data-base error: {0}")]
    DB(#[from] StorageError),
    #[error("{0} misses required dependencies {1:?}")]
    /// Will be returned when Scheduler tries to schedule a VT with missing dependencies
    MissingDependencies(Nvt, Vec<String>),
    #[error("invalid index ({0}) for Stage")]
    /// The index to create the stage is out of bounds
    InvalidStageIndex(usize),
    #[error("not found: {0}")]
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

impl From<&Nvt> for Stage {
    fn from(value: &Nvt) -> Self {
        match value.category {
            ACT::Init | ACT::Scanner | ACT::Settings | ACT::GatherInfo => Self::Discovery,
            ACT::Attack | ACT::MixedAttack => Self::NonEvasive,
            ACT::DestructiveAttack | ACT::Denial | ACT::KillHost | ACT::Flood => Self::Exhausting,
            ACT::End => Self::End,
        }
    }
}

impl From<Stage> for usize {
    fn from(value: Stage) -> Self {
        match value {
            Stage::Discovery => 0,
            Stage::NonEvasive => 1,
            Stage::Exhausting => 2,
            Stage::End => 3,
        }
    }
}

impl TryFrom<usize> for Stage {
    type Error = VTError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Stage::Discovery),
            1 => Ok(Stage::NonEvasive),
            2 => Ok(Stage::Exhausting),
            3 => Ok(Stage::End),
            a => Err(VTError::InvalidStageIndex(a)),
        }
    }
}

pub trait SchedulerStorage: Retriever<Oid, Item = Nvt> + Retriever<FileName, Item = Nvt> {}

impl SchedulerStorage for InMemoryStorage {}
impl<T: Write + Send> SchedulerStorage for JsonStorage<T> {}
impl<T> SchedulerStorage for RedisStorage<T> where
    T: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Send
{
}
impl<T: SchedulerStorage> SchedulerStorage for Arc<T> {}

/// Enhances the Retriever trait with execution_plan possibility.
pub trait ExecutionPlaner {
    /// Creates an execution plan based on the given scan using ExecutionPlan.
    ///
    /// To make it as inconvenient as possible for the caller to accidentally execute scripts that should
    /// not run concurrently in a concurrent fashion we return an iterator containing the stage as well
    /// as scripts that can be run concurrently instead of returning the struct that contains the stage
    /// data directly.
    ///
    /// If the second value (parameter) is None it indicates that this script in indirectly loaded
    /// and was not explicitly mentioned in the Scan.
    fn execution_plan<E>(
        &self,
        ids: &[VT],
    ) -> Result<impl Iterator<Item = ConcurrentVTResult>, VTError>
    where
        E: ExecutionPlan;
}

/// Contains the Nvt and maybe parameter required to be executed
type RuntimeVT = (Nvt, Option<Vec<Parameter>>);

/// Is the result of the Iterator if ExecutionPlaner
///
/// The reasoning to hide the structure behind an iterator of
/// (Stage, Vec<RuntimeVT>)
/// is to make it as inconvenient as possible to accidentally run scripts that
/// should not be run concurrently. Every item of the Vec of RuntimeVT can be run
/// concurrently. Each stage can, dependent on the ExecutionPlan, returned multiple
/// times with a list of scripts of to be run. To allow tracing when a stage changed
/// the stage information is given as well.
pub type ConcurrentVT = (Stage, Vec<RuntimeVT>);

/// The categorization or ordering of VT may error
pub type ConcurrentVTResult = Result<ConcurrentVT, VTError>;

/// To make it as inconvenient as possible for the caller to accidentally execute scripts that should
/// not run concurrently in a concurrent fashion we return an iterator containing the stage as well
/// as scripts that can be run concurrently instead of returning the struct that contains the stage
/// data.
/// See: issues/63063 impl Trait in type aliases is unstable
/// type ExecutionPlanerResult = Result<impl Iterator<Item = ConcurrentVTResult>, VTError>;
///
/// Is used by a ExecutionPlaner to order VTs in a specific manner and be returned.
///
/// It is meant to be used as an Iterator by the caller of ExecutionPlaner while the
/// ExecutionPlaner appends_vts.
pub trait ExecutionPlan: Iterator<Item = Result<Vec<RuntimeVT>, VTError>> + Default {
    /// Appends the given VT to an execution plan
    ///
    ///
    fn append_vt(
        &mut self,
        vts: RuntimeVT,
        dependency_lookup: &HashMap<String, Nvt>,
    ) -> Result<(), VTError>;
}

struct ExecutionPlanData<E>
where
    E: ExecutionPlan,
{
    data: [E; 4],
    idx: usize,
}

impl<E> ExecutionPlanData<E>
where
    E: ExecutionPlan,
{
    fn new(data: [E; 4]) -> Self {
        Self { data, idx: 0 }
    }
}

impl<E> Iterator for ExecutionPlanData<E>
where
    E: ExecutionPlan,
{
    type Item = ConcurrentVTResult;

    fn next(&mut self) -> Option<Self::Item> {
        let stage = Stage::try_from(self.idx).ok()?;
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

impl<T> ExecutionPlaner for T
where
    T: SchedulerStorage + ?Sized,
{
    fn execution_plan<E>(
        &self,
        scan_vts: &[VT],
    ) -> Result<impl Iterator<Item = ConcurrentVTResult>, VTError>
    where
        E: ExecutionPlan,
    {
        let mut results = core::array::from_fn(|_| E::default());
        let mut unknown_dependencies = Vec::new();
        let mut known_dependencies = HashMap::new();
        let mut vts = vec![];

        // Collect all VT information
        for vt in scan_vts {
            if let Some(nvt) = self.retrieve(&Oid(vt.oid.clone()))? {
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
            if let Some(nvt) = self.retrieve(&FileName(vt_name))? {
                unknown_dependencies.extend(nvt.dependencies.clone());
                known_dependencies.insert(nvt.filename.clone(), nvt);
            }
        }

        for (nvt, param) in vts.into_iter() {
            let stage = Stage::from(&nvt);
            tracing::trace!(?stage, oid = nvt.oid, "adding");
            results[usize::from(stage)].append_vt((nvt, param), &known_dependencies)?;
        }

        Ok(ExecutionPlanData::new(results))
    }
}

#[cfg(test)]
mod tests {
    use crate::models::VT;

    use crate::scanner::Scan;
    use crate::scheduling::ExecutionPlaner;
    use crate::scheduling::Stage;
    use crate::scheduling::WaveExecutionPlan;
    use crate::storage::Dispatcher;
    use crate::storage::inmemory::InMemoryStorage;
    use crate::storage::items::nvt::FileName;
    use crate::storage::items::nvt::Nvt;

    #[test]
    #[tracing_test::traced_test]
    fn load_dependencies() {
        let feed = vec![
            Nvt {
                oid: "0".to_string(),
                filename: "/0".to_string(),
                ..Default::default()
            },
            Nvt {
                oid: "1".to_string(),
                filename: "/1".to_string(),
                dependencies: vec!["/0".to_string()],
                ..Default::default()
            },
            Nvt {
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
        let results = storage
            .execution_plan::<WaveExecutionPlan>(&scan.vts)
            .expect("no error expected");
        assert_eq!(
            vec![
                (Stage::End, vec![(feed[0].clone(), None)]),
                (Stage::End, vec![(feed[1].clone(), None)]),
                (Stage::End, vec![(feed[2].clone(), Some(vec![]))]),
            ],
            results.filter_map(|x| x.ok()).collect::<Vec<_>>()
        )
    }
}
