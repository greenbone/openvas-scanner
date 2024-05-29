//! This module contains traits and implementations for scheduling a scan.
mod wave;

use storage::item::Nvt;
use thiserror::Error;
pub use wave::WaveExecutionPlan;
/// Error cases for VTFetcher
#[derive(Error, Debug, Clone)]
pub enum VTError {
    /// Underlying DB error.
    #[error("data-base error: {0}")]
    DB(#[from] storage::StorageError),
    /// Some VTs could not be processed.
    #[error("Contains unprocessed VTs. Process all Vts before iterating")]
    Unprocessed(Vec<Nvt>),
    #[error("Invalid index for Stage: {0}")]
    /// The index to create the stage is out o bounds
    InvalidStageIndex(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl From<&Nvt> for Stage {
    fn from(value: &Nvt) -> Self {
        match value.category {
            nasl_syntax::ACT::Init
            | nasl_syntax::ACT::Scanner
            | nasl_syntax::ACT::Settings
            | nasl_syntax::ACT::GatherInfo => Self::Discovery,
            nasl_syntax::ACT::Attack | nasl_syntax::ACT::MixedAttack => Self::NonEvasive,
            nasl_syntax::ACT::DestructiveAttack
            | nasl_syntax::ACT::Denial
            | nasl_syntax::ACT::KillHost
            | nasl_syntax::ACT::Flood => Self::Exhausting,
            nasl_syntax::ACT::End => Self::End,
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

/// Enhances the Retriever trait with execution_plan possibibility.
pub trait ExecutionPlaner {
    /// Creates an execution plan based on the given scan using ExecutionPlan impl E.
    ///
    /// To make it as inconvient as possible for the caller to accidentally execute scripts that should
    /// not run concurrently in a concurrent fashion we return an iterator containing the stage as well
    /// as scripts that can be run concurrently instead of returning the struct that contains the stage
    /// data directly.
    ///
    /// If the second value (parameter) is None it indicates that this script in indirectly loaded
    /// and was not explicitly mentioned in the Scan.
    ///
    /// # Example
    ///
    /// This examples shows the usage of the default implementation for a storage::Retriever to may
    /// help you understanding the behaviour for your own implementation or when using it.
    ///
    /// ```
    ///
    /// use nasl_interpreter::scheduling::ExecutionPlaner;
    /// use nasl_interpreter::scheduling::Stage;
    /// use nasl_interpreter::scheduling::WaveExecutionPlan;
    /// use storage::Dispatcher;
    /// use storage::Retriever;
    /// use storage::ContextKey;
    ///
    /// let feed = vec![
    ///     storage::item::Nvt {
    ///         oid: "0".to_string(),
    ///         filename: "/0".to_string(),
    ///         ..Default::default()
    ///     },
    ///     storage::item::Nvt {
    ///         oid: "1".to_string(),
    ///         filename: "/1".to_string(),
    ///         dependencies: vec!["/0".to_string()],
    ///         ..Default::default()
    ///     },
    ///     storage::item::Nvt {
    ///         oid: "2".to_string(),
    ///         filename: "/2".to_string(),
    ///         dependencies: vec!["/1".to_string()],
    ///         ..Default::default()
    ///     },
    /// ];
    /// let retrieve = storage::DefaultDispatcher::new(true);
    /// feed.clone().into_iter().for_each(|x| {
    ///     retrieve
    ///         .dispatch(&ContextKey::FileName(x.filename.clone()), x.into())
    ///         .expect("should store");
    /// });

    /// let scan = models::Scan {
    ///     vts: vec![models::VT {
    ///         oid: "2".to_string(),
    ///         parameters: vec![],
    ///     }],
    ///     ..Default::default()
    /// };
    /// let results = (&retrieve as &dyn Retriever)
    ///     .execution_plan::<WaveExecutionPlan>(&scan)
    ///     .expect("no error expected");
    /// assert_eq!(
    ///     vec![
    ///         (Stage::End, vec![(feed[0].clone(), None)]),
    ///         (Stage::End, vec![(feed[1].clone(), None)]),
    ///         (Stage::End, vec![(feed[2].clone(), Some(vec![]))]),
    ///     ],
    ///     results.filter_map(|x| x.ok()).collect::<Vec<_>>()
    /// )
    /// ```
    fn execution_plan<'a, E>(
        &self,
        ids: &'a models::Scan,
    ) -> Result<impl Iterator<Item = ConcurrentVTResult>, VTError>
    where
        E: ExecutionPlan;
}

/// Contains the Nvt and maybe parameter required to be executed
pub type RuntimeVT = (Nvt, Option<Vec<models::Parameter>>);

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

/// To make it as inconvient as possible for the caller to accidentally execute scripts that should
/// not run concurrently in a concurrent fashion we reutn an iterator containing the stage as well
/// as scripts that can be run concurrently instead of returning the struct that contains the stage
/// data.
/// See: issues/63063 impl Trait in type aliases is unstable
/// type ExecutionPlanerResult = Result<impl Iterator<Item = ConcurrentVTResult>, VTError>;

/// Is used by a ExecutionPlaner to order VTs in a specific manner and be returned.
///
/// It is meant to be used as an Iterator by the caller of ExecutionPlaner while the
/// ExecutionPlaner appends_vts.
pub trait ExecutionPlan: Iterator<Item = Result<Vec<RuntimeVT>, VTError>> + Default {
    /// Appends the given VT to an execution plan
    fn append_vt(
        &mut self,
        vt: Nvt,
        parameter: Option<Vec<models::Parameter>>,
    ) -> Result<(), VTError>;
}

struct ExeccutionPlanData<E>
where
    E: ExecutionPlan,
{
    data: [E; 4],
    idx: usize,
}

impl<E> ExeccutionPlanData<E>
where
    E: ExecutionPlan,
{
    fn new(data: [E; 4]) -> Self {
        Self { data, idx: 0 }
    }
}

impl<E> Iterator for ExeccutionPlanData<E>
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

impl ExecutionPlaner for dyn storage::Retriever
{
    fn execution_plan<'a, E>(
        &self,
        scan: &'a models::Scan,
    ) -> Result<impl Iterator<Item = ConcurrentVTResult>, VTError>
    where
        E: ExecutionPlan,
    {
        let oids: Vec<storage::Field> = scan
            .clone()
            .vts
            .into_iter()
            .map(|x| storage::item::NVTField::Oid(x.oid).into())
            .collect::<Vec<_>>();
        let mut results = core::array::from_fn(|_| E::default());
        let mut dependencies = Vec::new();
        for (i, x) in self
            .retrieve_by_fields(oids, storage::Retrieve::NVT(None))?
            .filter_map(|(_, f)| match f {
                storage::Field::NVT(storage::item::NVTField::Nvt(x)) => Some(x),
                _ => None,
            })
            .enumerate()
        {
            let stage = Stage::from(&x);
            tracing::trace!(?stage, oid = x.oid, "adding");
            let params: Option<Vec<models::Parameter>> =
                scan.vts.get(i).map(|x| x.parameters.clone());
            dependencies.extend(
                x.dependencies
                    .iter()
                    .map(|x| storage::Field::NVT(storage::item::NVTField::FileName(x.to_string()))),
            );
            results[usize::from(stage)].append_vt(x.clone(), params)?;
        }

        while !dependencies.is_empty() {
            dependencies = {
                let mut ret = Vec::new();
                for x in self
                    .retrieve_by_fields(dependencies, storage::Retrieve::NVT(None))?
                    .filter_map(|(_, f)| match f {
                        storage::Field::NVT(storage::item::NVTField::Nvt(x)) => Some(x),
                        _ => None,
                    })
                {
                    let stage = Stage::from(&x);
                    tracing::trace!(?stage, oid = x.oid, "adding script_dependency");
                    ret.extend(x.dependencies.iter().map(|x| {
                        storage::Field::NVT(storage::item::NVTField::FileName(x.to_string()))
                    }));
                    results[usize::from(stage)].append_vt(x.clone(), None)?;
                }
                ret
            }
        }

        Ok(ExeccutionPlanData::new(results))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[tracing_test::traced_test]
    fn load_dependencies() {
        use crate::scheduling::ExecutionPlaner;
        use crate::scheduling::Stage;
        use crate::scheduling::WaveExecutionPlan;
        use storage::Dispatcher;
        use storage::Retriever;

        let feed = vec![
            storage::item::Nvt {
                oid: "0".to_string(),
                filename: "/0".to_string(),
                ..Default::default()
            },
            storage::item::Nvt {
                oid: "1".to_string(),
                filename: "/1".to_string(),
                dependencies: vec!["/0".to_string()],
                ..Default::default()
            },
            storage::item::Nvt {
                oid: "2".to_string(),
                filename: "/2".to_string(),
                dependencies: vec!["/1".to_string()],
                ..Default::default()
            },
        ];
        let retrieve = storage::DefaultDispatcher::new(true);
        feed.clone().into_iter().for_each(|x| {
            retrieve
                .dispatch(&storage::ContextKey::default(), x.into())
                .expect("should store");
        });

        let scan = models::Scan {
            vts: vec![models::VT {
                oid: "2".to_string(),
                parameters: vec![],
            }],
            ..Default::default()
        };
        let results = (&retrieve as &dyn Retriever)
            .execution_plan::<WaveExecutionPlan>(&scan)
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
