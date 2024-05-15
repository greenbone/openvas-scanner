use std::collections::{HashMap, VecDeque};
use storage::item::Nvt;

use super::{ExecutionPlan, RuntimeVT, VTError};

/// Is a execution plan that only depends on script_dependencies.
///
/// It is based on the idea that each script that does not have any dependency will be executed
/// at index 0.
///
/// When a script only has dependencies that have no dependencies themselves it will be
/// executed at index 1.
///
/// When a script has depdencies that have dependencies themselves it will be executed at index 2
/// and so on.
///
#[derive(Default, Clone)]
pub struct WaveExecutionPlan {
    // filename is the key to identify quickly if a dependency is within a known index
    data: VecDeque<HashMap<String, RuntimeVT>>,
    unprocessed: Option<Vec<RuntimeVT>>,
    warned: bool,
}

impl WaveExecutionPlan {
    fn recheck(&mut self, unprocessed: Vec<RuntimeVT>) -> (bool, Vec<RuntimeVT>) {
        let mut recheck = false;
        let mut new_unprocessed = Vec::new();
        for (vt, param) in unprocessed.clone() {
            match self.find_index(&vt) {
                Some(i) => {
                    recheck = true;
                    self.insert_into(i, vt.filename.clone(), (vt, param))
                }
                None => new_unprocessed.push((vt, param)),
            }
        }
        (recheck, new_unprocessed)
    }

    fn check_unprocessed(&mut self) {
        if self.unprocessed.is_none() {
            return;
        }
        let mut unprocessed = self.unprocessed.clone().unwrap();
        let amount = unprocessed.len();

        tracing::trace!(amount, "checking unprocessed VTs");
        loop {
            let (recheck, new_unprocessed) = self.recheck(unprocessed.clone());
            if recheck {
                unprocessed = new_unprocessed;
            } else {
                break;
            }
        }

        if unprocessed.is_empty() {
            tracing::trace!(amount, "processed all Vts succesfully.");
            self.unprocessed = None;
        } else {
            tracing::trace!(amount = unprocessed.len(), "VTs have not processed.");
            self.unprocessed = Some(unprocessed);
        }
    }

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
        vt: Nvt,
        parameter: Option<Vec<models::Parameter>>,
    ) -> Result<(), VTError> {
        self.check_unprocessed();
        let index = self.find_index(&vt);
        let key = vt.filename.clone();
        let element = (vt, parameter);
        if let Some(i) = index {
            self.insert_into(i, key, element);
        } else {
            tracing::trace!(key, "unresolved dependencies");
            if self.unprocessed.is_none() {
                self.unprocessed = Some(vec![element]);
            } else {
                self.unprocessed
                    .iter_mut()
                    .for_each(|x| x.push(element.clone()))
            }
        }
        Ok(())
    }
}

impl Iterator for WaveExecutionPlan {
    type Item = Result<Vec<RuntimeVT>, VTError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.check_unprocessed();
        // if cleanup fails return error
        if let Some(unprocessed) = &self.unprocessed {
            if unprocessed.len() > 0 {
                if !self.warned {
                    let unprocessed = unprocessed
                        .into_iter()
                        .map(|(v, _)| v.clone())
                        .collect::<Vec<_>>();
                    tracing::warn!(unprocessed_len = unprocessed.len(), "unable process");
                    self.warned = true;
                    return Some(Err(VTError::Unprocessed(unprocessed)));
                } else {
                    return None;
                }
            }
        }

        let results = self.data.pop_front();
        results.map(|x| Ok(x.into_iter().map(|(_, e)| e).collect::<Vec<_>>()))
    }
}

#[cfg(test)]
mod tests {
    use storage::item::Nvt;

    use crate::scheduling::{ConcurrentVTResult, Stage};

    use super::WaveExecutionPlan;

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
        fn pick_exhausting_stage(idx: usize) -> nasl_syntax::ACT {
            match idx % 4 {
                3 => nasl_syntax::ACT::DestructiveAttack,
                2 => nasl_syntax::ACT::Denial,
                1 => nasl_syntax::ACT::KillHost,
                _ => nasl_syntax::ACT::Flood,
            }
        }
        fn pick_non_evasive_stage(idx: usize) -> nasl_syntax::ACT {
            match idx % 2 {
                1 => nasl_syntax::ACT::Attack,
                _ => nasl_syntax::ACT::MixedAttack,
            }
        }
        fn pick_discovery_stage(idx: usize) -> nasl_syntax::ACT {
            match idx % 4 {
                3 => nasl_syntax::ACT::GatherInfo,
                2 => nasl_syntax::ACT::Scanner,
                1 => nasl_syntax::ACT::GatherInfo,
                _ => nasl_syntax::ACT::Init,
            }
        }

        fn generate_stage(
            oid_gen: &mut OidGenerator,
            amount: usize,
            f: &dyn Fn(usize) -> nasl_syntax::ACT,
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
            results.extend(Self::generate_stage(&mut oid_gen, self.end, &|_| {
                nasl_syntax::ACT::End
            }));
            results
        }

        fn generate_pyramid_stage(
            oid_gen: &mut OidGenerator,
            lowest: usize,
            f: &dyn Fn(usize) -> nasl_syntax::ACT,
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
                &|_| nasl_syntax::ACT::End,
            ));
            results
        }
    }

    fn create_results<F, F2>(vt_gen: F, pick: F2) -> Vec<ConcurrentVTResult>
    where
        F: Fn() -> Vec<Nvt>,
        F2: Fn(Vec<Nvt>) -> Vec<Nvt>,
    {
        use crate::scheduling::ExecutionPlaner;
        use storage::Dispatcher;
        use storage::Retriever;
        let nvts = vt_gen();
        let retrieve = storage::DefaultDispatcher::new(true);
        nvts.clone().into_iter().for_each(|x| {
            retrieve
                .dispatch(&storage::ContextKey::default(), x.into())
                .expect("should store");
        });
        let scan_vts = pick(nvts)
            .iter()
            .map(|n| models::VT {
                oid: n.oid.clone(),
                parameters: vec![],
            })
            .collect();

        let scan = models::Scan {
            vts: scan_vts,
            ..Default::default()
        };
        let results = (&retrieve as &dyn Retriever)
            .execution_plan::<WaveExecutionPlan>(&scan)
            .ok()
            .unwrap();
        results.collect()
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
            |x| x.last().map(|x| x.clone()).into_iter().collect(),
        );

        let mut non_evasive_scipt_calls = Vec::with_capacity(4);
        for r in results
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|(s, _)| s == &Stage::NonEvasive)
            .map(|(_, r)| r)
        {
            non_evasive_scipt_calls.push(r.len());
        }
        assert_eq!(
            generator.nonevasive,
            non_evasive_scipt_calls.len(),
            "expect a list of VTs per dependency depth"
        );
        for i in 0..generator.nonevasive {
            assert_eq!(
                generator.nonevasive - i,
                non_evasive_scipt_calls[i],
                "expect {} scripts in depth {} of ConservativeExecutionPlan",
                generator.nonevasive - i,
                i
            );
        }
        assert_eq!(
            (generator.nonevasive * (generator.nonevasive + 1) / 2) as usize,
            non_evasive_scipt_calls.iter().sum(),
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
        let results = create_results(
            || vts.clone(),
            |x| x.last().map(|x| x.clone()).into_iter().collect(),
        );
        assert_eq!(results.iter().filter(|x| matches!(x, Ok(_))).count(), 0);
        assert_eq!(results.iter().filter(|x| matches!(x, Err(_))).count(), 1);
    }
}
