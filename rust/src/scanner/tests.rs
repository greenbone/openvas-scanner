use super::Scan;
use super::preferences::preference::ScanPrefs;
use crate::models::Phase;
use crate::models::Protocol;
use crate::models::VT;
use crate::models::scanner::{ScanResultFetcher, ScanResults};
use crate::nasl::ScanCtxBuilder;
use crate::nasl::interpreter::ForkingInterpreter;
use crate::nasl::nasl_std_functions;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::Executor;
use crate::nasl::utils::Register;
use crate::nasl::utils::scan_ctx::Target;
use crate::scanner::Scanner;
use crate::scanner::{
    error::{ExecuteError, ScriptResult},
    scan_runner::ScanRunner,
};
use crate::scheduling::{ExecutionPlaner, WaveExecutionPlan};
use crate::storage::Dispatcher;
use crate::storage::Retriever;
use crate::storage::ScanID;
use crate::storage::inmemory::InMemoryStorage;
use crate::storage::items::kb;
use crate::storage::items::kb::KbContextKey;
use crate::storage::items::kb::KbItem;
use crate::storage::items::kb::KbKey;
use crate::storage::items::nvt::FileName;
use crate::storage::items::nvt::Nvt;

use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing_test::traced_test;

type TestStack = (Arc<InMemoryStorage>, fn(&str) -> String);

pub fn setup(scripts: &[(String, Nvt)]) -> (TestStack, Executor, Scan) {
    let storage = InMemoryStorage::new();
    scripts.iter().map(|(_, v)| v).for_each(|n| {
        storage
            .dispatch(FileName(n.filename.clone()), n.clone())
            .expect("sending")
    });
    let scan = Scan {
        scan_id: "sid".to_string(),
        targets: vec![Target::do_not_resolve_hostname("test.host")],
        ports: Default::default(),
        vts: scripts
            .iter()
            .map(|(_, v)| VT {
                oid: v.oid.clone(),
                parameters: vec![],
            })
            .collect(),
        scan_preferences: ScanPrefs::new(),
        alive_test_methods: Vec::new(),
        alive_test_ports: Vec::new(),
    };
    let executor = nasl_std_functions();
    ((Arc::new(storage), loader), executor, scan)
}

fn make_scanner_and_scan_success() -> (Scanner<TestStack>, Scan) {
    let ((storage, loader), executor, scan) = setup(&only_success());
    (Scanner::new(storage, loader, executor), scan)
}

fn make_scanner_and_scan(scripts: &[(String, Nvt)]) -> (Scanner<TestStack>, Scan) {
    let ((storage, loader), executor, scan) = setup(scripts);
    (Scanner::new(storage, loader, executor), scan)
}

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

fn parse_meta_data(filename: &str, code: &str) -> Option<Nvt> {
    let initial = vec![
        ("description".to_owned(), true.into()),
        ("OPENVAS_VERSION".to_owned(), "testus".into()),
    ];
    let storage = Arc::new(InMemoryStorage::new());

    let register = Register::root_initial(&initial);
    let target = Target::localhost();
    let ports = Default::default();
    let executor = nasl_std_functions();
    let loader = |_: &str| code.to_string();
    let scan_id = ScanID(filename.to_string());
    let scan_preferences = ScanPrefs::new();
    let alive_test_methods = Vec::default();
    let cb = ScanCtxBuilder {
        storage: &storage,
        loader: &loader,
        executor: &executor,
        scan_id,
        target,
        ports,
        filename,
        scan_preferences,
        alive_test_methods,
    };
    let context = cb.build();
    let interpreter = ForkingInterpreter::new(code, register, &context);
    for stmt in interpreter.iter_blocking() {
        if let NaslValue::Exit(_) = stmt.expect("stmt success") {
            break;
        }
    }
    drop(context);
    storage
        .retrieve(&FileName(filename.to_string()))
        .expect("nvt for id")
}

fn prepare_vt_storage(scripts: &[(String, Nvt)]) -> InMemoryStorage {
    let dispatcher = InMemoryStorage::new();
    scripts.iter().map(|(_, v)| v).for_each(|n| {
        dispatcher
            .dispatch(FileName(n.filename.clone()), n.clone())
            .expect("sending")
    });
    dispatcher
}

async fn run(
    scripts: Vec<(String, Nvt)>,
    storage: Arc<InMemoryStorage>,
) -> Result<Vec<Result<ScriptResult, ExecuteError>>, ExecuteError> {
    let stou = |s: &str| s.split('.').next().unwrap().parse::<usize>().unwrap();
    let loader_scripts = scripts.clone();
    let loader = move |s: &str| loader_scripts[stou(s)].0.clone();
    let scan = Scan {
        scan_id: "sid".to_string(),
        targets: vec![Target::do_not_resolve_hostname("test.host")],
        ports: Default::default(),
        vts: scripts
            .iter()
            .map(|(_, v)| VT {
                oid: v.oid.clone(),
                parameters: vec![],
            })
            .collect(),
        scan_preferences: ScanPrefs::new(),
        alive_test_methods: Vec::new(),
        alive_test_ports: Vec::new(),
    };

    let executor = nasl_std_functions();

    let schedule = storage.execution_plan::<WaveExecutionPlan>(&scan.vts)?;
    let interpreter: ScanRunner<(_, _)> =
        ScanRunner::new(&storage, &loader, &executor, schedule, &scan)?;
    let results = interpreter.stream().collect::<Vec<_>>().await;
    Ok(results)
}

async fn get_all_results(
    vts: &[(String, Nvt)],
    storage: Arc<InMemoryStorage>,
) -> (Vec<ScriptResult>, Vec<ScriptResult>) {
    let result = run(vts.to_vec(), storage).await.expect("success run");
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
        GenerateScript::with_required_ports("0", &[(Protocol::UDP, "2000"), (Protocol::TCP, "20")])
            .generate(),
        GenerateScript::with_required_ports("1", &[(Protocol::UDP, "2000"), (Protocol::TCP, "2")])
            .generate(),
        GenerateScript::with_required_ports("2", &[(Protocol::UDP, "200"), (Protocol::TCP, "20")])
            .generate(),
        GenerateScript::with_required_ports("3", &[(Protocol::UDP, "2000"), (Protocol::TCP, "22")])
            .generate(),
        GenerateScript::with_required_ports("4", &[(Protocol::UDP, "2002"), (Protocol::TCP, "20")])
            .generate(),
    ];
    let storage = Arc::new(prepare_vt_storage(&vts));
    [
        (Protocol::TCP, "20", 1),   // TCP 20 is considered enabled
        (Protocol::TCP, "22", 0),   // TCP 22 is considered disabled
        (Protocol::UDP, "2000", 1), // UDP 2000 is considered enabled
        (Protocol::UDP, "2002", 0), // UDP 2002 is considered disabled
    ]
    .into_iter()
    .for_each(|(p, port, enabled)| {
        storage
            .dispatch(
                KbContextKey(
                    (
                        ScanID("sid".to_string()),
                        crate::storage::Target("test.host".to_string()),
                    ),
                    match p {
                        Protocol::UDP => KbKey::Port(kb::Port::Udp(port.to_string())),
                        Protocol::TCP => KbKey::Port(kb::Port::Tcp(port.to_string())),
                    },
                ),
                KbItem::Number(enabled),
            )
            .expect("store kb");
    });
    let (success, failure) = get_all_results(&vts, storage).await;
    assert_eq!(success.len(), 1);
    assert_eq!(failure.len(), 4);
}

fn make_test_storage(vts: &[(String, Nvt)]) -> Arc<InMemoryStorage> {
    let storage = prepare_vt_storage(vts);
    storage
        .dispatch(
            KbContextKey(
                (
                    ScanID("sid".to_string()),
                    crate::storage::Target("test.host".to_string()),
                ),
                KbKey::Custom("key/exists".to_string()),
            ),
            KbItem::Number(1),
        )
        .expect("store kb");
    Arc::new(storage)
}

#[tokio::test]
#[tracing_test::traced_test]
async fn exclude_keys() {
    let only_success = [
        GenerateScript::with_excluded_keys("0", &["key/not"]).generate(),
        GenerateScript::with_excluded_keys("1", &["key/not"]).generate(),
        GenerateScript::with_excluded_keys("2", &["key/exists"]).generate(),
    ];
    let storage = make_test_storage(&only_success);
    let (success, failure) = get_all_results(&only_success, storage).await;
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
    let dispatcher = make_test_storage(&only_success);
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
    let dispatcher = make_test_storage(&only_success);
    let (success, failure) = get_all_results(&only_success, dispatcher).await;
    assert_eq!(success.len(), 1);
    assert_eq!(failure.len(), 1);
}

async fn wait_for_status(scanner: Scanner<TestStack>, id: &str, phase: Phase) -> ScanResults {
    const TIMEOUT: u128 = 500;
    let start = Instant::now();
    loop {
        // we need the sleep to not instantly read lock running and preventing write access
        tokio::time::sleep(Duration::from_nanos(100)).await;
        let scan_results = scanner
            .fetch_results(id.to_string())
            .await
            .expect("no error when fetching results");
        if scan_results.status.status == phase {
            return scan_results;
        }
        let delta = start.elapsed();
        if delta.as_millis() > TIMEOUT {
            tracing::debug!(status=%scan_results.status.status, expected=%phase);

            panic!("timeout reached");
        }
    }
}

#[tokio::test]
#[traced_test]
async fn start_scan_failure() {
    let failures = [GenerateScript {
        id: "0".into(),
        rc: 1,
        ..Default::default()
    }
    .generate()];

    let (scanner, scan) = make_scanner_and_scan(&failures);

    let id = scan.scan_id.clone();
    let res = scanner.start_scan_internal(scan).await;
    assert!(res.is_ok());
    let scan_results = wait_for_status(scanner, &id, Phase::Succeeded).await;

    assert!(
        scan_results.status.start_time.is_some(),
        "expect start time to be set when scan starts"
    );
    assert!(
        scan_results.status.end_time.is_some(),
        "expect end time to be set when scan finished"
    );
    assert!(
        scan_results.status.host_info.is_some(),
        "host_info should be set"
    );
    let host_info = scan_results.status.host_info.unwrap();
    assert_eq!(host_info.finished, 1);
    assert_eq!(host_info.queued, 0);
}

#[tokio::test]
#[traced_test]
async fn start_scan_success() {
    let (scanner, mut scan) = make_scanner_and_scan_success();
    scan.targets
        .push(Target::do_not_resolve_hostname("wald.fee"));

    let id = scan.scan_id.clone();
    let res = scanner.start_scan_internal(scan).await;
    assert!(res.is_ok());
    let scan_results = wait_for_status(scanner, &id, Phase::Succeeded).await;

    assert!(
        scan_results.status.start_time.is_some(),
        "expect start time to be set when scan starts"
    );
    assert!(
        scan_results.status.end_time.is_some(),
        "expect end time to be set when scan finished"
    );
    assert!(
        scan_results.status.host_info.is_some(),
        "host_info should be set"
    );
    let host_info = scan_results.status.host_info.unwrap();
    assert_eq!(host_info.finished, 2);
    assert_eq!(host_info.queued, 0);
}
