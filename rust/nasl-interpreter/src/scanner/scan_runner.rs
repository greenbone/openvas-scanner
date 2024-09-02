// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use futures::{stream, Stream};
use models::{Host, HostInfo, Scan};
use nasl_builtin_utils::Executor;

use crate::scanner::ScannerStack;
use crate::scheduling::ConcurrentVT;

use super::error::{ExecuteError, ScriptResult};
use super::scanner_stack::Schedule;
use super::vt_runner::VTRunner;

#[derive(Default, Debug, Clone, Copy)]
struct Position {
    host: usize,
    stage: usize,
    vt: usize,
}

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

/// TODO: doc
pub struct ScanRunner<'a, S: ScannerStack> {
    scan: &'a models::Scan,
    storage: &'a S::Storage,
    loader: &'a S::Loader,
    executor: &'a Executor,
    concurrent_vts: Vec<ConcurrentVT>,
}

impl<'a, Stack: ScannerStack> ScanRunner<'a, Stack> {
    /// TODO doc
    pub fn new<Sched>(
        storage: &'a Stack::Storage,
        loader: &'a Stack::Loader,
        executor: &'a Executor,
        schedule: Sched,
        scan: &'a Scan,
    ) -> Self
    where
        Sched: Schedule + 'a,
    {
        // TODO dont unwrap here
        let concurrent_vts = schedule.cache().unwrap();
        Self {
            scan,
            storage,
            loader,
            executor,
            concurrent_vts,
        }
    }

    /// TODO doc
    pub fn host_info(&self) -> HostInfo {
        HostInfo::from_hosts_and_num_vts(&self.scan.target.hosts, self.concurrent_vts.len())
    }

    /// Todo doc
    pub fn stream(self) -> impl Stream<Item = Result<ScriptResult, ExecuteError>> + 'a {
        let data = all_positions(self.scan.target.hosts.clone(), self.concurrent_vts.clone()).map(
            move |pos| {
                let (stage, vts) = &self.concurrent_vts[pos.stage];
                let (vt, param) = &vts[pos.vt];
                let host = &self.scan.target.hosts[pos.host];
                (
                    stage.clone(),
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
    use futures::StreamExt;
    use nasl_builtin_utils::Executor;
    use storage::item::Nvt;
    use storage::Dispatcher;
    use storage::Retriever;

    use crate::nasl_std_functions;
    use crate::scanner::error::ExecuteError;
    use crate::scanner::error::ScriptResult;
    use crate::scanner::scan_runner::ScanRunner;
    use crate::scanner::vt_runner::generate_port_kb_key;
    use crate::scheduling::ExecutionPlaner;
    use crate::scheduling::WaveExecutionPlan;

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
        scripts: &[(String, storage::item::Nvt)],
    ) -> (
        (storage::DefaultDispatcher, fn(&str) -> String, Executor),
        models::Scan,
    ) {
        use storage::Dispatcher;
        let storage = storage::DefaultDispatcher::new();
        scripts.iter().map(|(_, v)| v).for_each(|n| {
            storage
                .dispatch(
                    &storage::ContextKey::FileName(n.filename.clone()),
                    storage::Field::NVT(storage::item::NVTField::Nvt(n.clone())),
                )
                .expect("sending")
        });
        let scan = models::Scan {
            scan_id: "sid".to_string(),
            target: models::Target {
                hosts: vec!["test.host".to_string()],
                ..Default::default()
            },
            scan_preferences: vec![],
            vts: scripts
                .iter()
                .map(|(_, v)| models::VT {
                    oid: v.oid.clone(),
                    parameters: vec![],
                })
                .collect(),
        };
        let executor = nasl_std_functions();
        ((storage, loader, executor), scan)
    }

    pub fn setup_success() -> (
        (storage::DefaultDispatcher, fn(&str) -> String, Executor),
        models::Scan,
    ) {
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

        pub fn with_required_ports(id: &str, ports: &[(models::Protocol, &str)]) -> GenerateScript {
            let required_tcp_ports = ports
                .iter()
                .filter(|(p, _)| matches!(p, models::Protocol::TCP))
                .map(|(_, p)| p.to_string())
                .collect();
            let required_udp_ports = ports
                .iter()
                .filter(|(p, _)| matches!(p, models::Protocol::UDP))
                .map(|(_, p)| p.to_string())
                .collect();

            GenerateScript {
                id: id.to_string(),
                required_tcp_ports,
                required_udp_ports,

                ..Default::default()
            }
        }

        pub fn generate(&self) -> (String, storage::item::Nvt) {
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
log_message(data: "Ja, junge dat is Kaffee, echt jetzt, und Kaffee ist nun mal lecker.");
exit({rc});
"#
            );
            let filename = format!("{id}.nasl");
            let nvt = parse_meta_data(&filename, &code).expect("expected metadata");
            (code, nvt)
        }
    }

    fn parse_meta_data(id: &str, code: &str) -> Option<storage::item::Nvt> {
        let initial = vec![
            ("description".to_owned(), true.into()),
            ("OPENVAS_VERSION".to_owned(), "testus".into()),
        ];
        let storage = storage::DefaultDispatcher::new();

        let register = nasl_builtin_utils::Register::root_initial(&initial);
        let target = String::default();
        let functions = nasl_std_functions();
        let loader = |_: &str| code.to_string();
        let key = storage::ContextKey::FileName(id.to_string());

        let context =
            nasl_builtin_utils::Context::new(key, target, &storage, &storage, &loader, &functions);
        let interpreter = crate::CodeInterpreter::new(code, register, &context);
        for stmt in interpreter.iter_blocking() {
            if let nasl_syntax::NaslValue::Exit(_) = stmt.expect("stmt success") {
                storage.on_exit(context.key()).expect("result");
                let result = storage
                    .retrieve(
                        &storage::ContextKey::FileName(id.to_string()),
                        storage::Retrieve::NVT(None),
                    )
                    .expect("nvt for id")
                    .next();
                if let Some(storage::Field::NVT(storage::item::NVTField::Nvt(nvt))) = result {
                    return Some(nvt);
                } else {
                    return None;
                }
            }
        }
        None
    }

    fn prepare_vt_storage(scripts: &[(String, storage::item::Nvt)]) -> storage::DefaultDispatcher {
        let dispatcher = storage::DefaultDispatcher::new();
        scripts.iter().map(|(_, v)| v).for_each(|n| {
            dispatcher
                .dispatch(
                    &storage::ContextKey::FileName(n.filename.clone()),
                    storage::Field::NVT(storage::item::NVTField::Nvt(n.clone())),
                )
                .expect("sending")
        });
        dispatcher
    }

    async fn run(
        scripts: Vec<(String, storage::item::Nvt)>,
        storage: storage::DefaultDispatcher,
    ) -> Result<Vec<Result<ScriptResult, ExecuteError>>, ExecuteError> {
        let stou = |s: &str| s.split('.').next().unwrap().parse::<usize>().unwrap();
        let loader_scripts = scripts.clone();
        let loader = move |s: &str| loader_scripts[stou(s)].0.clone();
        let scan = models::Scan {
            scan_id: "sid".to_string(),
            target: models::Target {
                hosts: vec!["test.host".to_string()],
                ..Default::default()
            },
            scan_preferences: vec![],
            vts: scripts
                .iter()
                .map(|(_, v)| models::VT {
                    oid: v.oid.clone(),
                    parameters: vec![],
                })
                .collect(),
        };

        let executor = nasl_std_functions();

        let schedule = storage.execution_plan::<WaveExecutionPlan>(&scan)?;
        let interpreter: ScanRunner<(_, _)> =
            ScanRunner::new(&storage, &loader, &executor, schedule, &scan);
        let results = interpreter.stream().collect::<Vec<_>>().await;
        Ok(results)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn required_ports() {
        let vts = [
            GenerateScript::with_required_ports(
                "0",
                &[
                    (models::Protocol::UDP, "2000"),
                    (models::Protocol::TCP, "20"),
                ],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "1",
                &[
                    (models::Protocol::UDP, "2000"),
                    (models::Protocol::TCP, "2"),
                ],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "2",
                &[
                    (models::Protocol::UDP, "200"),
                    (models::Protocol::TCP, "20"),
                ],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "3",
                &[
                    (models::Protocol::UDP, "2000"),
                    (models::Protocol::TCP, "22"),
                ],
            )
            .generate(),
            GenerateScript::with_required_ports(
                "4",
                &[
                    (models::Protocol::UDP, "2002"),
                    (models::Protocol::TCP, "20"),
                ],
            )
            .generate(),
        ];
        let dispatcher = prepare_vt_storage(&vts);
        [
            (models::Protocol::TCP, "20", 1),   // TCP 20 is considered enabled
            (models::Protocol::TCP, "22", 0),   // TCP 22 is considered disabled
            (models::Protocol::UDP, "2000", 1), // UDP 2000 is considered enabled
            (models::Protocol::UDP, "2002", 0), // UDP 2002 is considered disabled
        ]
        .into_iter()
        .for_each(|(p, port, enabled)| {
            dispatcher
                .dispatch(
                    &storage::ContextKey::Scan("sid".into(), Some("test.host".into())),
                    storage::Field::KB((&generate_port_kb_key(p, port), enabled).into()),
                )
                .expect("store kb");
        });
        let result = run(vts.to_vec(), dispatcher).await.expect("success run");
        let success = result
            .clone()
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_succeeded())
            .collect::<Vec<_>>();
        let failure = result
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_failed())
            .filter(|x| x.has_not_run())
            .collect::<Vec<_>>();
        assert_eq!(success.len(), 1);
        assert_eq!(failure.len(), 4);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn exclude_keys() {
        let only_success = [
            GenerateScript::with_excluded_keys("0", &["key/not"]).generate(),
            GenerateScript::with_excluded_keys("1", &["key/not"]).generate(),
            GenerateScript::with_excluded_keys("2", &["key/exists"]).generate(),
        ];
        let dispatcher = prepare_vt_storage(&only_success);
        dispatcher
            .dispatch(
                &storage::ContextKey::Scan("sid".into(), Some("test.host".into())),
                storage::Field::KB(("key/exists", 1).into()),
            )
            .expect("store kb");
        let result = run(only_success.to_vec(), dispatcher)
            .await
            .expect("success run");
        let success = result
            .clone()
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_succeeded())
            .collect::<Vec<_>>();
        let failure = result
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_failed())
            .filter(|x| x.has_not_run())
            .collect::<Vec<_>>();
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
        let dispatcher = prepare_vt_storage(&only_success);
        dispatcher
            .dispatch(
                &storage::ContextKey::Scan("sid".into(), Some("test.host".into())),
                storage::Field::KB(("key/exists", 1).into()),
            )
            .expect("store kb");
        let result = run(only_success.to_vec(), dispatcher)
            .await
            .expect("success run");
        let success = result
            .clone()
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_succeeded())
            .collect::<Vec<_>>();
        let failure = result
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_failed())
            .filter(|x| x.has_not_run())
            .collect::<Vec<_>>();
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
        let dispatcher = prepare_vt_storage(&only_success);
        dispatcher
            .dispatch(
                &storage::ContextKey::Scan("sid".into(), Some("test.host".to_string())),
                storage::Field::KB(("key/exists", 1).into()),
            )
            .expect("store kb");
        let result = run(only_success.to_vec(), dispatcher)
            .await
            .expect("success run");
        let success = result
            .clone()
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_succeeded())
            .collect::<Vec<_>>();
        let failure = result
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_failed())
            .filter(|x| x.has_not_run())
            .collect::<Vec<_>>();
        assert_eq!(success.len(), 1);
        assert_eq!(failure.len(), 1);
    }
}
