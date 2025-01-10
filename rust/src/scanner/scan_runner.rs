// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::{Host, HostInfo, Scan};
use crate::nasl::utils::Executor;
use futures::{stream, Stream};

use crate::scanner::ScannerStack;
use crate::scheduling::{ConcurrentVT, VTError};

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
fn all_positions(hosts: Vec<Host>, vts: Vec<ConcurrentVT>) -> impl Iterator<Item = Position> {
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
        HostInfo::from_hosts_and_num_vts(&self.scan.target.hosts, self.concurrent_vts.len())
    }

    pub fn stream(self) -> impl Stream<Item = Result<ScriptResult, ExecuteError>> + 'a {
        let data = all_positions(self.scan.target.hosts.clone(), self.concurrent_vts.clone()).map(
            move |pos| {
                let (stage, vts) = &self.concurrent_vts[pos.stage];
                let (vt, param) = &vts[pos.vt];
                let host = &self.scan.target.hosts[pos.host];
                (
                    *stage,
                    vt.clone(),
                    param.clone(),
                    host.clone(),
                    self.scan.scan_id.clone(),
                )
            },
        );
        // The usage of unfold here will prevent any real asynchronous running of VTs
        // and automatically guarantee that we stick to the scheduling requirements.
        // If this is changed, make sure to uphold the scheduling requirements in the
        // new implementation.
        stream::unfold(data, move |mut data| async move {
            if let Some((stage, vt, param, host, scan_id)) = data.next() {
                let result = VTRunner::<Stack>::run(
                    self.storage,
                    self.loader,
                    self.executor,
                    &host,
                    &vt,
                    stage,
                    param.as_ref(),
                    &scan_id,
                )
                .await;
                Some((result, data))
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use crate::models::Protocol;
    use crate::models::Scan;
    use crate::models::Target;
    use crate::models::VT;
    use crate::nasl::syntax::NaslValue;
    use crate::nasl::utils::context::Target as ContextTarget;
    use crate::nasl::utils::Context;
    use crate::nasl::utils::Executor;
    use crate::nasl::utils::Register;
    use crate::nasl::{interpreter::CodeInterpreter, nasl_std_functions};
    use crate::scanner::{
        error::{ExecuteError, ScriptResult},
        scan_runner::ScanRunner,
        vt_runner::generate_port_kb_key,
    };
    use crate::scheduling::{ExecutionPlaner, WaveExecutionPlan};
    use crate::storage::item::NVTField;
    use crate::storage::item::Nvt;
    use crate::storage::ContextKey;
    use crate::storage::DefaultDispatcher;
    use crate::storage::Dispatcher;
    use crate::storage::Field;
    use crate::storage::Field::NVT;
    use crate::storage::Retrieve;
    use crate::storage::Retriever;
    use futures::StreamExt;

    pub fn only_success() -> [(String, Nvt); 3] {
        [
            GenerateScript::with_dependencies("0", &[]).generate(),
            GenerateScript::with_dependencies("1", &["0.nasl"]).generate(),
            GenerateScript::with_dependencies("2", &["1.nasl"]).generate(),
        ]
    }

    fn loader(s: &str) -> String {
        let only_success = only_success();
        let stou = |s: &str| s.split('.').next().unwrap().parse::<usize>().unwrap();
        only_success[stou(s)].0.clone()
    }

    pub fn setup(
        scripts: &[(String, Nvt)],
    ) -> ((DefaultDispatcher, fn(&str) -> String, Executor), Scan) {
        let storage = DefaultDispatcher::new();
        scripts.iter().map(|(_, v)| v).for_each(|n| {
            storage
                .dispatch(
                    &ContextKey::FileName(n.filename.clone()),
                    NVT(NVTField::Nvt(n.clone())),
                )
                .expect("sending")
        });
        let scan = Scan {
            scan_id: "sid".to_string(),
            target: Target {
                hosts: vec!["test.host".to_string()],
                ..Default::default()
            },
            scan_preferences: vec![],
            vts: scripts
                .iter()
                .map(|(_, v)| VT {
                    oid: v.oid.clone(),
                    parameters: vec![],
                })
                .collect(),
        };
        let executor = nasl_std_functions();
        ((storage, loader, executor), scan)
    }

    pub fn setup_success() -> ((DefaultDispatcher, fn(&str) -> String, Executor), Scan) {
        setup(&only_success())
    }

    #[derive(Debug, Default)]
    pub struct GenerateScript {
        pub id: String,
        pub rc: usize,
        pub dependencies: Vec<String>,
        pub required_keys: Vec<String>,
        pub mandatory_keys: Vec<String>,
        pub required_tcp_ports: Vec<String>,
        pub required_udp_ports: Vec<String>,
        pub exclude: Vec<String>,
    }

    impl GenerateScript {
        pub fn with_dependencies(id: &str, dependencies: &[&str]) -> GenerateScript {
            let dependencies = dependencies.iter().map(|x| x.to_string()).collect();

            GenerateScript {
                id: id.to_string(),
                dependencies,
                ..Default::default()
            }
        }

        pub fn with_required_keys(id: &str, required_keys: &[&str]) -> GenerateScript {
            let required_keys = required_keys.iter().map(|x| x.to_string()).collect();
            GenerateScript {
                id: id.to_string(),
                required_keys,
                ..Default::default()
            }
        }

        pub fn with_mandatory_keys(id: &str, mandatory_keys: &[&str]) -> GenerateScript {
            let mandatory_keys = mandatory_keys.iter().map(|x| x.to_string()).collect();
            GenerateScript {
                id: id.to_string(),
                mandatory_keys,
                ..Default::default()
            }
        }

        pub fn with_excluded_keys(id: &str, exclude_keys: &[&str]) -> GenerateScript {
            let exclude = exclude_keys.iter().map(|x| x.to_string()).collect();
            GenerateScript {
                id: id.to_string(),
                exclude,
                ..Default::default()
            }
        }

        pub fn with_required_ports(id: &str, ports: &[(Protocol, &str)]) -> GenerateScript {
            let required_tcp_ports = ports
                .iter()
                .filter(|(p, _)| matches!(p, Protocol::TCP))
                .map(|(_, p)| p.to_string())
                .collect();
            let required_udp_ports = ports
                .iter()
                .filter(|(p, _)| matches!(p, Protocol::UDP))
                .map(|(_, p)| p.to_string())
                .collect();

            GenerateScript {
                id: id.to_string(),
                required_tcp_ports,
                required_udp_ports,

                ..Default::default()
            }
        }

        pub fn generate(&self) -> (String, Nvt) {
            let keys = |x: &[String]| -> String {
                x.iter().fold(String::default(), |acc, e| {
                    let acc = if acc.is_empty() {
                        acc
                    } else {
                        format!("{acc}, ")
                    };
                    format!("\"{acc}{e}\"")
                })
            };
            let printable = |name, x| -> String {
                let dependencies = keys(x);
                if dependencies.is_empty() {
                    String::default()
                } else {
                    format!("{name}({dependencies});")
                }
            };
            let mandatory = printable("script_mandatory_keys", &self.mandatory_keys);
            let required = printable("script_require_keys", &self.required_keys);
            let dependencies = printable("script_dependencies", &self.dependencies);
            let exclude = printable("script_exclude_keys", &self.exclude);
            let require_ports = printable("script_require_ports", &self.required_tcp_ports);
            let require_udp_ports = printable("script_require_udp_ports", &self.required_udp_ports);

            let rc = self.rc;
            let id = &self.id;

            let code = format!(
                r#"
if (description)
{{
  script_oid("{id}");
  script_category(ACT_GATHER_INFO);
  {dependencies}
  {mandatory}
  {required}
  {exclude}
  {require_ports}
  {require_udp_ports}
  exit(0);
}}
log_message(data: "Hello world.");
exit({rc});
"#
            );
            let filename = format!("{id}.nasl");
            let nvt = parse_meta_data(&filename, &code).expect("expected metadata");
            (code, nvt)
        }
    }

    fn parse_meta_data(id: &str, code: &str) -> Option<Nvt> {
        let initial = vec![
            ("description".to_owned(), true.into()),
            ("OPENVAS_VERSION".to_owned(), "testus".into()),
        ];
        let storage = DefaultDispatcher::new();

        let register = Register::root_initial(&initial);
        let target = ContextTarget::default();
        let functions = nasl_std_functions();
        let loader = |_: &str| code.to_string();
        let key = ContextKey::FileName(id.to_string());

        let context = Context::new(key, target, &storage, &storage, &loader, &functions);
        let interpreter = CodeInterpreter::new(code, register, &context);
        for stmt in interpreter.iter_blocking() {
            if let NaslValue::Exit(_) = stmt.expect("stmt success") {
                storage.on_exit(context.key()).expect("result");
                let result = storage
                    .retrieve(&ContextKey::FileName(id.to_string()), Retrieve::NVT(None))
                    .expect("nvt for id")
                    .next();
                if let Some(NVT(NVTField::Nvt(nvt))) = result {
                    return Some(nvt);
                } else {
                    return None;
                }
            }
        }
        None
    }

    fn prepare_vt_storage(scripts: &[(String, Nvt)]) -> DefaultDispatcher {
        let dispatcher = DefaultDispatcher::new();
        scripts.iter().map(|(_, v)| v).for_each(|n| {
            dispatcher
                .dispatch(
                    &ContextKey::FileName(n.filename.clone()),
                    NVT(NVTField::Nvt(n.clone())),
                )
                .expect("sending")
        });
        dispatcher
    }

    async fn run(
        scripts: Vec<(String, Nvt)>,
        storage: DefaultDispatcher,
    ) -> Result<Vec<Result<ScriptResult, ExecuteError>>, ExecuteError> {
        let stou = |s: &str| s.split('.').next().unwrap().parse::<usize>().unwrap();
        let loader_scripts = scripts.clone();
        let loader = move |s: &str| loader_scripts[stou(s)].0.clone();
        let scan = Scan {
            scan_id: "sid".to_string(),
            target: Target {
                hosts: vec!["test.host".to_string()],
                ..Default::default()
            },
            scan_preferences: vec![],
            vts: scripts
                .iter()
                .map(|(_, v)| VT {
                    oid: v.oid.clone(),
                    parameters: vec![],
                })
                .collect(),
        };

        let executor = nasl_std_functions();

        let schedule = storage.execution_plan::<WaveExecutionPlan>(&scan)?;
        let interpreter: ScanRunner<(_, _)> =
            ScanRunner::new(&storage, &loader, &executor, schedule, &scan)?;
        let results = interpreter.stream().collect::<Vec<_>>().await;
        Ok(results)
    }

    async fn get_all_results(
        vts: &[(String, Nvt)],
        dispatcher: DefaultDispatcher,
    ) -> (Vec<ScriptResult>, Vec<ScriptResult>) {
        let result = run(vts.to_vec(), dispatcher).await.expect("success run");
        let (success, rest): (Vec<_>, Vec<_>) = result
            .into_iter()
            .filter_map(|x| x.ok())
            .partition(|x| x.has_succeeded());
        let failure = rest
            .into_iter()
            .filter(|x| !x.has_succeeded() && x.has_not_run())
            .collect();
        (success, failure)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn required_ports() {
        let vts = [
            GenerateScript::with_required_ports(
                "0",
                &[(Protocol::UDP, "2000"), (Protocol::TCP, "20")],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "1",
                &[(Protocol::UDP, "2000"), (Protocol::TCP, "2")],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "2",
                &[(Protocol::UDP, "200"), (Protocol::TCP, "20")],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "3",
                &[(Protocol::UDP, "2000"), (Protocol::TCP, "22")],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "4",
                &[(Protocol::UDP, "2002"), (Protocol::TCP, "20")],
            )
            .generate(),
        ];
        let dispatcher = prepare_vt_storage(&vts);
        [
            (Protocol::TCP, "20", 1),   // TCP 20 is considered enabled
            (Protocol::TCP, "22", 0),   // TCP 22 is considered disabled
            (Protocol::UDP, "2000", 1), // UDP 2000 is considered enabled
            (Protocol::UDP, "2002", 0), // UDP 2002 is considered disabled
        ]
        .into_iter()
        .for_each(|(p, port, enabled)| {
            dispatcher
                .dispatch(
                    &ContextKey::Scan("sid".into(), Some("test.host".into())),
                    Field::KB((&generate_port_kb_key(p, port), enabled).into()),
                )
                .expect("store kb");
        });
        let (success, failure) = get_all_results(&vts, dispatcher).await;
        assert_eq!(success.len(), 1);
        assert_eq!(failure.len(), 4);
    }

    fn make_test_dispatcher(vts: &[(String, Nvt)]) -> DefaultDispatcher {
        let dispatcher = prepare_vt_storage(vts);
        dispatcher
            .dispatch(
                &ContextKey::Scan("sid".into(), Some("test.host".into())),
                Field::KB(("key/exists", 1).into()),
            )
            .expect("store kb");
        dispatcher
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn exclude_keys() {
        let only_success = [
            GenerateScript::with_excluded_keys("0", &["key/not"]).generate(),
            GenerateScript::with_excluded_keys("1", &["key/not"]).generate(),
            GenerateScript::with_excluded_keys("2", &["key/exists"]).generate(),
        ];
        let dispatcher = make_test_dispatcher(&only_success);
        let (success, failure) = get_all_results(&only_success, dispatcher).await;
        assert_eq!(success.len(), 2);
        assert_eq!(failure.len(), 1);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn required_keys() {
        let only_success = [
            GenerateScript::with_required_keys("0", &["key/not"]).generate(),
            GenerateScript::with_required_keys("1", &["key/exists"]).generate(),
        ];
        let dispatcher = make_test_dispatcher(&only_success);
        let (success, failure) = get_all_results(&only_success, dispatcher).await;
        assert_eq!(success.len(), 1);
        assert_eq!(failure.len(), 1);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn mandatory_keys() {
        let only_success = [
            GenerateScript::with_mandatory_keys("0", &["key/not"]).generate(),
            GenerateScript::with_mandatory_keys("1", &["key/exists"]).generate(),
        ];
        let dispatcher = make_test_dispatcher(&only_success);
        let (success, failure) = get_all_results(&only_success, dispatcher).await;
        assert_eq!(success.len(), 1);
        assert_eq!(failure.len(), 1);
    }
}
