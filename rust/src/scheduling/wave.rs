// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::item::Nvt;
use std::collections::{HashMap, VecDeque};

use super::{ExecutionPlan, RuntimeVT, VTError};

/// Is a execution plan that only depends on script_dependencies.
///
/// It is based on the idea that each script that does not have any dependency will be executed
/// at index 0.
///
/// When a script only has dependencies that have no dependencies themselves it will be
/// executed at index 1.
///
/// When a script has dependencies that have dependencies themselves it will be executed at index 2
/// and so on.
///
#[derive(Default, Clone)]
pub struct WaveExecutionPlan {
    // filename is the key to identify quickly if a dependency is within a known index
    data: VecDeque<HashMap<String, RuntimeVT>>,
    dependencies_added: bool,
}

impl WaveExecutionPlan {
    fn insert_into(&mut self, index: usize, key: String, element: RuntimeVT) {
        tracing::trace!(key, index, "inserting");
        if self.data.len() <= index {
            let mut insert = HashMap::new();
            insert.insert(key, element);
            self.data.push_back(insert);
        } else {
            self.data[index].insert(key, element);
        }
    }

    fn find_index(&self, vt: &Nvt) -> Option<usize> {
        if vt.dependencies.is_empty() {
            Some(0)
        } else {
            let mut result = None;
            for n in vt.dependencies.iter() {
                if let Some(i) = self
                    .data
                    .iter()
                    .enumerate()
                    .find(|(_, x)| x.contains_key(n))
                    .map(|(i, _)| i + 1)
                {
                    if let Some(ci) = result {
                        if i > ci {
                            result = Some(i);
                        }
                    } else {
                        result = Some(i);
                    }
                } else {
                    tracing::debug!(script = vt.filename, dependency = n, "dependency not found");
                    return None;
                }
            }
            result
        }
    }
}

impl ExecutionPlan for WaveExecutionPlan {
    fn append_vt(
        &mut self,
        vt: RuntimeVT,
        dependencies: &HashMap<String, Nvt>,
    ) -> Result<(), VTError> {
        if !self.dependencies_added {
            self.dependencies_added = true;
            let mut unprocessed_dependencies = dependencies
                .values()
                .filter_map(|x| {
                    if let Some(i) = self.find_index(x) {
                        self.insert_into(i, x.filename.clone(), (x.clone(), None));
                        None
                    } else {
                        Some(x.clone())
                    }
                })
                .collect::<Vec<_>>();

            while !unprocessed_dependencies.is_empty() {
                let p = unprocessed_dependencies.clone();
                unprocessed_dependencies = unprocessed_dependencies
                    .into_iter()
                    .filter_map(|x| {
                        if let Some(i) = self.find_index(&x) {
                            self.insert_into(i, x.filename.clone(), (x, None));
                            None
                        } else {
                            Some(x)
                        }
                    })
                    .collect::<Vec<_>>();
                // no change
                if p == unprocessed_dependencies {
                    tracing::warn!(dependencies=?unprocessed_dependencies.into_iter().map(|v|v.filename).collect::<Vec<_>>(), "unable process vts");
                    // we continue and let it later run into missing dependencies later on
                    break;
                }
            }
        }

        let (vt, parameter) = vt;
        let index = self.find_index(&vt);
        let key = vt.filename.clone();
        let element = (vt, parameter);

        if let Some(i) = index {
            self.insert_into(i, key, element);
            Ok(())
        } else {
            tracing::trace!(key, "unresolved dependencies");
            let missing = element
                .0
                .dependencies
                .iter()
                .filter(|x| !self.data.iter().any(|y| y.contains_key(x as &str)))
                .cloned()
                .collect::<Vec<_>>();
            Err(VTError::MissingDependencies(element.0, missing))
        }
    }
}

impl Iterator for WaveExecutionPlan {
    type Item = Result<Vec<RuntimeVT>, VTError>;

    fn next(&mut self) -> Option<Self::Item> {
        let results = self.data.pop_front();
        results.map(|x| Ok(x.into_values().collect::<Vec<_>>()))
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{Scan, VT};

    use crate::nasl::syntax::ACT;
    use crate::storage::item::Nvt;

    use crate::scheduling::{ConcurrentVTResult, Stage};
    use crate::storage::{ContextKey, DefaultDispatcher};

    use super::WaveExecutionPlan;
    use crate::scheduling::ExecutionPlaner;
    use crate::storage::Dispatcher;
    use crate::storage::Retriever;

    struct OidGenerator {
        latest_number: u64,
    }

    impl OidGenerator {
        pub fn generate(&mut self, level: usize) -> String {
            let result = match level {
                0 => format!("0.0.0.0.0.0.{}", self.latest_number),
                1 => format!("0.0.0.0.0.{}.0", self.latest_number),
                2 => format!("0.0.0.0.{}.0.0", self.latest_number),
                3 => format!("0.0.0.{}.0.0.0", self.latest_number),
                4 => format!("0.0.{}.0.0.0.0", self.latest_number),
                5 => format!("0.{}.0.0.0.0.0", self.latest_number),
                _ => format!("{}.0.0.0.0.0.0", self.latest_number),
            };
            self.latest_number += 1;
            result
        }
    }

    struct NvtGenerator {
        discovery: usize,
        nonevasive: usize,
        exhausting: usize,
        end: usize,
    }

    impl NvtGenerator {
        fn pick_exhausting_stage(idx: usize) -> ACT {
            match idx % 4 {
                3 => ACT::DestructiveAttack,
                2 => ACT::Denial,
                1 => ACT::KillHost,
                _ => ACT::Flood,
            }
        }
        fn pick_non_evasive_stage(idx: usize) -> ACT {
            match idx % 2 {
                1 => ACT::Attack,
                _ => ACT::MixedAttack,
            }
        }
        fn pick_discovery_stage(idx: usize) -> ACT {
            match idx % 4 {
                3 => ACT::GatherInfo,
                2 => ACT::Scanner,
                1 => ACT::GatherInfo,
                _ => ACT::Init,
            }
        }

        fn generate_stage(
            oid_gen: &mut OidGenerator,
            amount: usize,
            f: &dyn Fn(usize) -> ACT,
        ) -> Vec<Nvt> {
            (0..amount)
                .map(|i| {
                    let oid = oid_gen.generate(0);

                    Nvt {
                        oid: oid.clone(),
                        category: f(i),
                        filename: format!("/{oid}"),
                        ..Default::default()
                    }
                })
                .collect::<Vec<_>>()
        }
        pub fn generate(&self) -> Vec<Nvt> {
            let mut oid_gen = OidGenerator { latest_number: 0 };
            let mut results =
                Self::generate_stage(&mut oid_gen, self.discovery, &Self::pick_discovery_stage);
            results.extend(Self::generate_stage(
                &mut oid_gen,
                self.nonevasive,
                &Self::pick_non_evasive_stage,
            ));
            results.extend(Self::generate_stage(
                &mut oid_gen,
                self.exhausting,
                &Self::pick_exhausting_stage,
            ));
            results.extend(Self::generate_stage(&mut oid_gen, self.end, &|_| ACT::End));
            results
        }

        fn generate_pyramid_stage(
            oid_gen: &mut OidGenerator,
            lowest: usize,
            f: &dyn Fn(usize) -> ACT,
        ) -> Vec<Nvt> {
            let mut results: Vec<Nvt> = Vec::with_capacity(lowest * (lowest + 1) / 2);
            for i in (0..=lowest).rev() {
                let mut dependencies = Self::generate_stage(oid_gen, i, f);
                if i != lowest {
                    let depdep = results
                        .iter()
                        .skip(results.len() - (i + 1))
                        .map(|x| x.filename.clone())
                        .collect::<Vec<_>>();

                    dependencies
                        .iter_mut()
                        .for_each(|j| j.dependencies.extend(depdep.clone()));
                }
                results.extend(dependencies);
            }
            results
        }

        pub fn generate_pyramid(&self) -> Vec<Nvt> {
            let mut oid_gen = OidGenerator { latest_number: 0 };
            let mut results = Self::generate_pyramid_stage(
                &mut oid_gen,
                self.discovery,
                &Self::pick_discovery_stage,
            );
            results.extend(Self::generate_pyramid_stage(
                &mut oid_gen,
                self.nonevasive,
                &Self::pick_non_evasive_stage,
            ));
            results.extend(Self::generate_pyramid_stage(
                &mut oid_gen,
                self.exhausting,
                &Self::pick_exhausting_stage,
            ));
            results.extend(Self::generate_pyramid_stage(
                &mut oid_gen,
                self.end,
                &|_| ACT::End,
            ));
            results
        }
    }

    fn create_results_iter<F, F2>(
        vt_gen: F,
        pick: F2,
    ) -> Result<Vec<ConcurrentVTResult>, super::VTError>
    where
        F: Fn() -> Vec<Nvt>,
        F2: Fn(Vec<Nvt>) -> Vec<Nvt>,
    {
        let nvts = vt_gen();
        let retrieve = DefaultDispatcher::new();
        nvts.clone().into_iter().for_each(|x| {
            retrieve
                .dispatch(&ContextKey::default(), x.into())
                .expect("should store");
        });
        let scan_vts = pick(nvts)
            .iter()
            .map(|n| VT {
                oid: n.oid.clone(),
                parameters: vec![],
            })
            .collect();

        let scan = Scan {
            vts: scan_vts,
            ..Default::default()
        };
        let results = (&retrieve as &dyn Retriever).execution_plan::<WaveExecutionPlan>(&scan);

        results.map(|x| x.collect())
    }

    fn create_results<F, F2>(vt_gen: F, pick: F2) -> Vec<ConcurrentVTResult>
    where
        F: Fn() -> Vec<Nvt>,
        F2: Fn(Vec<Nvt>) -> Vec<Nvt>,
    {
        create_results_iter(vt_gen, pick).expect("expected results")
    }

    #[test]
    #[tracing_test::traced_test]
    fn load_dependencies() {
        let generator = NvtGenerator {
            discovery: 0,
            nonevasive: 15,
            exhausting: 0,
            end: 0,
        };
        let results = create_results(
            || generator.generate_pyramid(),
            |x| x.last().cloned().into_iter().collect(),
        );

        let mut non_evasive_script_calls = Vec::with_capacity(4);
        for r in results
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|(s, _)| s == &Stage::NonEvasive)
            .map(|(_, r)| r)
        {
            non_evasive_script_calls.push(r.len());
        }
        assert_eq!(
            generator.nonevasive,
            non_evasive_script_calls.len(),
            "expect a list of VTs per dependency depth"
        );

        non_evasive_script_calls
            .iter()
            .enumerate()
            .take(generator.nonevasive)
            .for_each(|(i, r)| {
                assert_eq!(
                    generator.nonevasive - i,
                    *r,
                    "expect {} scripts in depth {} of ConservativeExecutionPlan",
                    generator.nonevasive - i,
                    i
                );
            });

        assert_eq!(
            { generator.nonevasive * (generator.nonevasive + 1) / 2 },
            non_evasive_script_calls.iter().sum::<usize>(),
            "expect each known VT to be called"
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn phase_sort_remove_duplicates() {
        let generator = NvtGenerator {
            discovery: 100,
            nonevasive: 100,
            exhausting: 10,
            end: 1,
        };
        let mut vts = generator.generate();
        vts.extend(vts.clone());
        let results = create_results(|| vts.clone(), |x| x);
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::Discovery)
                .flat_map(|(_, x)| x)
                .count(),
            generator.discovery
        );
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::NonEvasive)
                .flat_map(|(_, x)| x)
                .count(),
            generator.nonevasive
        );
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::Exhausting)
                .flat_map(|(_, x)| x)
                .count(),
            generator.exhausting
        );
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::End)
                .flat_map(|(_, x)| x)
                .count(),
            generator.end
        );
    }
    #[test]
    #[tracing_test::traced_test]
    fn phase_sort_stages() {
        let generator = NvtGenerator {
            discovery: 100,
            nonevasive: 100,
            exhausting: 10,
            end: 1,
        };

        let results = create_results(|| generator.generate(), |x| x);
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::Discovery)
                .flat_map(|(_, x)| x)
                .count(),
            generator.discovery
        );
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::NonEvasive)
                .flat_map(|(_, x)| x)
                .count(),
            generator.nonevasive
        );
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::Exhausting)
                .flat_map(|(_, x)| x)
                .count(),
            generator.exhausting
        );
        assert_eq!(
            results
                .clone()
                .into_iter()
                .filter_map(|x| x.ok())
                .filter(|(s, _)| s == &Stage::End)
                .flat_map(|(_, x)| x)
                .count(),
            generator.end
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn circular_dependency() {
        let generator = NvtGenerator {
            discovery: 3,
            nonevasive: 0,
            exhausting: 0,
            end: 0,
        };
        let mut vts = generator.generate_pyramid();
        let with_dependency = vts.last().unwrap();
        let to_be_add = with_dependency.filename.to_string();
        let to_be_found = with_dependency.dependencies.first().unwrap().to_string();
        vts.iter_mut()
            .filter(|x| x.oid == to_be_found[1..])
            .for_each(|x| x.dependencies.push(to_be_add.clone()));
        let results =
            create_results_iter(|| vts.clone(), |x| x.last().cloned().into_iter().collect());
        assert!(results.is_err())
    }

    #[test]
    #[tracing_test::traced_test]
    fn return_error_once_on_missing_dependencies() {
        let generator = NvtGenerator {
            discovery: 15,
            nonevasive: 0,
            exhausting: 0,
            end: 0,
        };
        let mut vts = generator.generate_pyramid();
        vts.reverse();
        let _ = vts.pop();
        vts.reverse();
        let results =
            create_results_iter(|| vts.clone(), |x| x.last().cloned().into_iter().collect());
        assert!(results.is_err())
    }
}
