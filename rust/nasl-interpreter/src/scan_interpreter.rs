// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! scan-interpreter interprets models::Scan

use nasl_builtin_utils::NaslFunctionExecuter;
use nasl_syntax::{Loader, NaslValue};
use storage::{types::Primitive, ContextKey, Storage};

use crate::{scheduling::ExecutionPlaner, InterpretError};

/// Runs a scan in a synchronous mode
///
/// As a Scan is able to configure the behavior of scripts (e.g. consider_alive means that each
/// port within the scan is considered reachable without testing) each Interpreter must be created
/// for each scan and is not reusable.
pub struct SyncScanInterpreter<'a, S, L, N> {
    storage: &'a S,
    loader: &'a L,
    function_executor: N,
}

#[derive(thiserror::Error, Debug, Clone)]
/// An error occurred while executing the script
pub enum ExecuteError {
    #[error("storage error occurred: {0}")]
    /// Storage error
    Storage(#[from] storage::StorageError),
    #[error("Scheduling error occurred: {0}")]
    /// An error while scheduling
    Scheduling(#[from] crate::scheduling::VTError),
    #[error("unable to load: {0}")]
    /// Script was not found
    NotFound(#[from] nasl_syntax::LoadError),
    #[error("unable to handle parameter: {0}")]
    /// The parameter could not be processed
    Parameter(models::Parameter),
}
#[derive(Debug, Clone)]
/// Contains the result of a executed script
pub enum ScriptResultKind {
    /// Contains the code provided by exit call or 0 when script finished successful without exit
    /// call
    ReturnCode(i64),
    /// Is missing a port
    MissingPort(models::Protocol, String),
    /// Script did not run because an excluded key is set
    ContainsExcludedKey(String),
    /// Script did not run because of missing required keys
    ///
    /// It contains the first not found key.
    MissingRequiredKey(String),
    /// Script did not run because of missing mandatory keys
    ///
    /// It contains the first not found key.
    MissingMandatoryKey(String),
    /// Contains the error the script returned
    Error(InterpretError),
}

#[derive(Debug, Clone)]
/// Contains meta data of the script and its result
pub struct ScriptResult {
    /// Object identifier of the script
    pub oid: String,
    /// relative filename of the script
    pub filename: String,
    /// the stage of the script
    pub stage: crate::scheduling::Stage,
    /// the result
    pub kind: ScriptResultKind,
}

impl ScriptResult {
    /// Returns true when the return code of the script is 0.
    pub fn has_succeeded(&self) -> bool {
        matches!(&self.kind, ScriptResultKind::ReturnCode(0))
    }
    /// Returns true when the return code of the script not 0
    pub fn has_failed(&self) -> bool {
        !self.has_succeeded()
    }

    /// Returns true when the script didn't run
    pub fn has_not_run(&self) -> bool {
        matches!(
            self.kind,
            ScriptResultKind::MissingRequiredKey(_)
                | ScriptResultKind::MissingMandatoryKey(_)
                | ScriptResultKind::ContainsExcludedKey(_)
                | ScriptResultKind::MissingPort(..)
        )
    }
}
pub(crate) fn generate_port_kb_key(protocol: models::Protocol, port: &str) -> String {
    format!("Ports/{protocol}/{port}")
}

struct ScriptExecutor<'a, T> {
    schedule: T,
    scan: &'a models::Scan,

    /// Default Retriever
    storage: &'a dyn Storage,
    /// Default Loader
    loader: &'a dyn Loader,
    /// Default function executor.
    executor: &'a dyn NaslFunctionExecuter,
    // index of the current host within scan
    current_host: Option<usize>,
    handled_hosts: usize,
    current_results: Option<crate::scheduling::ConcurrentVTResult>,
}

impl<'a, T> ScriptExecutor<'a, T>
where
    T: Iterator<Item = crate::scheduling::ConcurrentVTResult> + 'a,
{
    pub fn new<S, L, N>(
        scan: &'a models::Scan,
        storage: &'a S,
        loader: &'a L,
        executor: &'a N,
        schedule: T,
    ) -> Self
    where
        S: Storage,
        L: Loader,
        N: NaslFunctionExecuter,
    {
        let current_host = if scan.target.hosts.is_empty() {
            None
        } else {
            Some(0)
        };
        Self {
            schedule,
            scan,
            storage,
            loader,
            executor,
            current_results: None,
            current_host,
            handled_hosts: 0,
        }
    }
    // TODO: implement
    fn parameter(
        &mut self,
        parameter: &models::Parameter,
        _register: &mut crate::Register,
    ) -> Result<(), ExecuteError> {
        Err(ExecuteError::Parameter(parameter.clone()))
    }

    fn check_key<A, B, C>(
        &self,
        key: &storage::ContextKey,
        kb_key: &str,
        result_none: A,
        result_some: B,
        result_err: C,
    ) -> Result<(), ScriptResultKind>
    where
        A: Fn() -> Option<ScriptResultKind>,
        B: Fn(Primitive) -> Option<ScriptResultKind>,
        C: Fn(storage::StorageError) -> Option<ScriptResultKind>,
    {
        let _span = tracing::error_span!("kb_item", %key, kb_key).entered();
        let result = match self
            .storage
            .retrieve(key, storage::Retrieve::KB(kb_key.to_string()))
        {
            Ok(mut x) => {
                let x = x.next();
                if let Some(x) = x {
                    match x {
                        storage::Field::KB(kb) => {
                            tracing::trace!(value=?kb.value, "found");
                            result_some(kb.value)
                        }
                        x => {
                            tracing::trace!(field=?x, "found but it is not a KB item");
                            result_none()
                        }
                    }
                } else {
                    tracing::trace!("not found");
                    result_none()
                }
            }
            Err(e) => {
                tracing::warn!(error=%e, "storage error");
                result_err(e)
            }
        };
        match result {
            None => Ok(()),
            Some(x) => Err(x),
        }
    }

    fn check_keys(&self, vt: &storage::item::Nvt) -> Result<(), ScriptResultKind> {
        let key = ContextKey::Scan(self.scan.scan_id.clone());
        let check_required_key = |k: &str| {
            self.check_key(
                &key,
                k,
                || Some(ScriptResultKind::MissingRequiredKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingRequiredKey(k.into())),
            )
        };
        for k in &vt.required_keys {
            check_required_key(k)?
        }

        let check_mandatory_key = |k: &str| {
            self.check_key(
                &key,
                k,
                || Some(ScriptResultKind::MissingMandatoryKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingMandatoryKey(k.into())),
            )
        };
        for k in &vt.mandatory_keys {
            check_mandatory_key(k)?
        }

        let check_exclude_key = |k: &str| {
            self.check_key(
                &key,
                k,
                || None,
                |_| Some(ScriptResultKind::ContainsExcludedKey(k.into())),
                |_| None,
            )
        };
        for k in &vt.excluded_keys {
            check_exclude_key(k)?
        }

        use models::Protocol;
        let check_port = |pt: Protocol, port: &str| {
            let kbk = generate_port_kb_key(pt, port);
            self.check_key(
                &key,
                &kbk,
                || Some(ScriptResultKind::MissingPort(pt, port.to_string())),
                |v| {
                    if v.into() {
                        None
                    } else {
                        Some(ScriptResultKind::MissingPort(pt, port.to_string()))
                    }
                },
                |_| Some(ScriptResultKind::MissingPort(pt, port.to_string())),
            )
        };
        for k in &vt.required_ports {
            check_port(Protocol::TCP, k)?
        }
        for k in &vt.required_udp_ports {
            check_port(Protocol::UDP, k)?
        }

        Ok(())
    }

    // TODO: probably better to enhance ContextKey::Scan to contain target and scan_id?
    fn generate_key(&self, target: &str) -> ContextKey {
        ContextKey::Scan(format!("{}-{}", self.scan.scan_id, target))
    }

    fn execute(
        &mut self,
        stage: crate::scheduling::Stage,
        vt: storage::item::Nvt,
        param: Option<Vec<models::Parameter>>,
    ) -> Result<ScriptResult, ExecuteError> {
        let code = self.loader.load(&vt.filename)?;
        let target = match self.current_host {
            None => unreachable!("host check must be done in the iterator implementation"),
            Some(i) => self.scan.target.hosts[i].to_string(),
        };
        let mut register = crate::Register::default();
        if let Some(params) = param {
            for p in params.iter() {
                self.parameter(p, &mut register)?;
            }
        }

        let _span = tracing::span!(
            tracing::Level::WARN,
            "executing",
            filename = &vt.filename,
            oid = &vt.oid,
            %stage,
            target,
        )
        .entered();

        // currently scans are limited to the target as well as the id.
        tracing::debug!("running");
        let kind = {
            match self.check_keys(&vt) {
                Err(e) => e,
                Ok(()) => {
                    let context = crate::Context::new(
                        self.generate_key(&target),
                        target,
                        self.storage.as_dispatcher(),
                        self.storage.as_retriever(),
                        self.loader,
                        self.executor,
                    );
                    let mut interpret = crate::CodeInterpreter::new(&code, register, &context);

                    interpret
                        .find_map(|r| match r {
                            Ok(NaslValue::Exit(x)) => Some(ScriptResultKind::ReturnCode(x)),
                            Err(e) => Some(ScriptResultKind::Error(e.clone())),
                            Ok(x) => {
                                tracing::trace!(statement_result=?x);
                                None
                            }
                        })
                        .unwrap_or_else(|| ScriptResultKind::ReturnCode(0))
                }
            }
        };
        tracing::debug!(result=?kind, "finished");
        Ok(ScriptResult {
            oid: vt.oid,
            filename: vt.filename,
            stage,
            kind,
        })
    }
}

impl<'a, T> Iterator for ScriptExecutor<'a, T>
where
    T: Iterator<Item = crate::scheduling::ConcurrentVTResult> + 'a,
{
    type Item = Result<ScriptResult, ExecuteError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_results.is_none() {
            match self.schedule.next() {
                Some(Err(e)) => return Some(Err(e.into())),
                result => self.current_results = result,
            }
        }
        if self.current_host.is_none() {
            self.handled_hosts += 1;
            if self.scan.target.hosts.len() < self.handled_hosts {
                self.current_host = Some(self.handled_hosts);
            } else {
                // finished
                return None;
            }
        }
        let (stage, vt, param) = match self.current_results.as_mut() {
            Some(Ok((stage, vts))) => match vts.pop() {
                Some((vt, param)) => (stage.clone(), vt.clone(), param.clone()),
                None => {
                    // stage is finished
                    self.current_results = None;
                    return self.next();
                }
            },
            Some(Err(_)) => {
                unreachable!("error handling of sef.schedule.next is be done before to not run into borrow issues");
            }
            None => {
                // TODO: cleanup target specific keys
                // host is finished
                self.current_host = None;
                return self.next();
            }
        };

        Some(self.execute(stage, vt, param))
    }
}

impl<'a, S, L> SyncScanInterpreter<'a, S, L, crate::NaslFunctionRegister>
where
    S: Storage,
    L: Loader,
{
    /// Creates a SyncScanInterpreter with nasl_std_functions set.
    pub fn with_default_function_executor(
        storage: &'a S,
        loader: &'a L,
    ) -> SyncScanInterpreter<'a, S, L, crate::NaslFunctionRegister> {
        SyncScanInterpreter {
            storage,
            loader,
            function_executor: crate::nasl_std_functions(),
        }
    }
}
impl<'a, S, L, N> SyncScanInterpreter<'a, S, L, N>
where
    S: storage::Storage,
    L: nasl_syntax::Loader,
    N: NaslFunctionExecuter,
{
    /// Creates a new SyncScanInterpreter
    ///
    /// It uses a scan to execute all configured vts within that scan.
    pub fn new(storage: &'a S, loader: &'a L, function_executor: N) -> Self {
        Self {
            storage,
            loader,
            function_executor,
        }
    }
    /// Runs the given scan based on the given schedule.
    ///
    /// Uses the given schedule to run each vt in scan.
    ///
    /// To execute all vt the iterator must be fully consumed.
    ///
    /// ## Example
    ///
    /// In this example we create an artificial feed with a single script that just exits with 0.
    ///
    /// ```
    /// use nasl_interpreter::scheduling::ExecutionPlaner;
    /// use nasl_interpreter::scheduling::WaveExecutionPlan;
    /// use nasl_interpreter::SyncScanInterpreter;
    /// use storage::Dispatcher;
    /// // create fake data
    /// let nvt = storage::item::Nvt {
    ///     oid: "0".to_string(),
    ///     filename: format!("0.nasl"),
    ///     ..Default::default()
    /// };
    /// let loader = |x:&str| "exit(0);".to_string();
    /// let store = storage::DefaultDispatcher::default();
    /// store.dispatch(&storage::ContextKey::FileName("0.nasl".into()), nvt.into());
    /// // use that for scanning
    /// let scan = models::Scan {
    ///     scan_id: "sid".to_string(),
    ///     target: models::Target {
    ///         hosts: vec!["test.host".to_string()],
    ///         ..Default::default()
    ///     },
    ///     scan_preferences: vec![],
    ///     vts: vec![models::VT {
    ///             oid: "0".to_string(),
    ///             parameters: vec![],
    ///         }],
    /// };
    /// let schedule = store
    ///   .execution_plan::<WaveExecutionPlan>(&scan)
    ///   .expect("expected to be schedulable");
    /// let interpreter = SyncScanInterpreter::with_default_function_executor(
    ///        &store, &loader,
    /// );
    /// interpreter.run_with_schedule(&scan, schedule).unwrap().for_each(|x|println!("{x:?}"));
    ///
    /// ```
    pub fn run_with_schedule<T>(
        &'a self,
        scan: &'a models::Scan,
        schedule: T,
    ) -> Result<impl Iterator<Item = Result<ScriptResult, ExecuteError>> + 'a, ExecuteError>
    where
        T: Iterator<Item = crate::scheduling::ConcurrentVTResult> + 'a,
    {
        // TODO: set scan parameter
        // TODO: remove non alive target#hosts
        // TODO: either save whole scan or partial ports into storage
        // We have to reconstruct:
        // set Host/scanned TRUE when host tcp is scanned
        // set Host/scanners/$name TRUE
        // set Host/udp_scanned when host udp is scanned
        // set port status of each preference by:
        // - Ports/tcp/port/$port value 0 for closed or 1 for open
        // - Ports/udp/port/$port value 0 for closed or 1 for open
        // TODO: set kb item ports
        Ok(ScriptExecutor::new::<S, L, N>(
            scan,
            self.storage,
            self.loader,
            &self.function_executor,
            schedule,
        ))
    }

    /// Runs the given scan
    ///
    /// Uses the storage to create a scheduling plan T to utilize that to execute the scripts
    /// within scan by returning an iterator of ScriptResults.
    ///
    /// To execute all vt the iterator must be fully consumed.
    ///
    /// ## Example
    ///
    /// In this example we create an artificial feed with a single script that just exits with 0.
    ///
    /// ```
    /// use nasl_interpreter::scheduling::ExecutionPlaner;
    /// use nasl_interpreter::scheduling::WaveExecutionPlan;
    /// use nasl_interpreter::SyncScanInterpreter;
    /// use storage::Dispatcher;
    /// // create fake data
    /// let nvt = storage::item::Nvt {
    ///     oid: "0".to_string(),
    ///     filename: format!("0.nasl"),
    ///     ..Default::default()
    /// };
    /// let loader = |x:&str| "exit(0);".to_string();
    /// let store = storage::DefaultDispatcher::default();
    /// store.dispatch(&storage::ContextKey::FileName("0.nasl".into()), nvt.into());
    /// // use that for scanning
    /// let scan = models::Scan {
    ///     scan_id: "sid".to_string(),
    ///     target: models::Target {
    ///         hosts: vec!["test.host".to_string()],
    ///         ..Default::default()
    ///     },
    ///     scan_preferences: vec![],
    ///     vts: vec![models::VT {
    ///             oid: "0".to_string(),
    ///             parameters: vec![],
    ///         }],
    /// };
    /// let interpreter = SyncScanInterpreter::with_default_function_executor(
    ///        &store, &loader,
    /// );
    /// interpreter.run::<WaveExecutionPlan>(&scan).unwrap().for_each(|x|println!("{x:?}"));
    ///
    /// ```
    pub fn run<T>(
        &'a self,
        scan: &'a models::Scan,
    ) -> Result<impl Iterator<Item = Result<ScriptResult, ExecuteError>> + 'a, ExecuteError>
    where
        T: crate::scheduling::ExecutionPlan + 'a,
    {
        let schedule = self.storage.execution_plan::<T>(scan)?;
        self.run_with_schedule(scan, schedule)
    }
}

#[cfg(test)]
mod tests {
    use storage::{Dispatcher, Retriever};

    #[derive(Debug, Default)]
    struct GenerateScript {
        id: String,
        rc: usize,
        dependencies: Vec<String>,
        required_keys: Vec<String>,
        mandatory_keys: Vec<String>,
        required_tcp_ports: Vec<String>,
        required_udp_ports: Vec<String>,
        exclude: Vec<String>,
    }

    impl GenerateScript {
        fn with_dependencies(id: &str, dependencies: &[&str]) -> GenerateScript {
            let dependencies = dependencies.iter().map(|x| x.to_string()).collect();

            GenerateScript {
                id: id.to_string(),
                dependencies,
                ..Default::default()
            }
        }

        fn with_required_keys(id: &str, required_keys: &[&str]) -> GenerateScript {
            let required_keys = required_keys.iter().map(|x| x.to_string()).collect();
            GenerateScript {
                id: id.to_string(),
                required_keys,
                ..Default::default()
            }
        }

        fn with_mandatory_keys(id: &str, mandatory_keys: &[&str]) -> GenerateScript {
            let mandatory_keys = mandatory_keys.iter().map(|x| x.to_string()).collect();
            GenerateScript {
                id: id.to_string(),
                mandatory_keys,
                ..Default::default()
            }
        }

        fn with_excluded_keys(id: &str, exclude_keys: &[&str]) -> GenerateScript {
            let exclude = exclude_keys.iter().map(|x| x.to_string()).collect();
            GenerateScript {
                id: id.to_string(),
                exclude,
                ..Default::default()
            }
        }

        fn with_required_ports(id: &str, ports: &[(models::Protocol, &str)]) -> GenerateScript {
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

        fn generate(&self) -> (String, storage::item::Nvt) {
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
        let storage = storage::DefaultDispatcher::new(true);

        let register = nasl_builtin_utils::Register::root_initial(&initial);
        let target = String::default();
        let functions = crate::nasl_std_functions();
        let loader = |_: &str| code.to_string();

        let context = nasl_builtin_utils::Context::new(
            storage::ContextKey::FileName(id.to_string()),
            target,
            &storage,
            &storage,
            &loader,
            &functions,
        );
        let interpreter = crate::CodeInterpreter::new(code, register, &context);
        for stmt in interpreter {
            if let nasl_syntax::NaslValue::Exit(_) = stmt.expect("stmt success") {
                storage.on_exit().expect("result");
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
        let dispatcher = storage::DefaultDispatcher::new(true);
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

    fn run(
        scripts: &[(String, storage::item::Nvt)],
        storage: storage::DefaultDispatcher,
    ) -> Result<Vec<Result<crate::ScriptResult, crate::ExecuteError>>, crate::ExecuteError> {
        let stou = |s: &str| s.split('.').next().unwrap().parse::<usize>().unwrap();
        let loader = |s: &str| scripts[stou(s)].0.clone();
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
        let interpreter =
            super::SyncScanInterpreter::with_default_function_executor(&storage, &loader);
        let results = interpreter
            .run::<crate::scheduling::WaveExecutionPlan>(&scan)?
            .collect::<Vec<_>>();
        Ok(results)
    }

    #[test]
    #[tracing_test::traced_test]
    fn required_ports() {
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
                    &storage::ContextKey::Scan("sid".into()),
                    storage::Field::KB((&super::generate_port_kb_key(p, port), enabled).into()),
                )
                .expect("store kb");
        });
        let result = run(&vts, dispatcher).expect("success run");
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

    #[test]
    #[tracing_test::traced_test]
    fn exclude_keys() {
        let only_success = [
            GenerateScript::with_excluded_keys("0", &["key/not"]).generate(),
            GenerateScript::with_excluded_keys("1", &["key/not"]).generate(),
            GenerateScript::with_excluded_keys("2", &["key/exists"]).generate(),
        ];
        let dispatcher = prepare_vt_storage(&only_success);
        dispatcher
            .dispatch(
                &storage::ContextKey::Scan("sid".into()),
                storage::Field::KB(("key/exists", 1).into()),
            )
            .expect("store kb");
        let result = run(&only_success, dispatcher).expect("success run");
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

    #[test]
    #[tracing_test::traced_test]
    fn required_keys() {
        let only_success = [
            GenerateScript::with_required_keys("0", &["key/not"]).generate(),
            GenerateScript::with_required_keys("1", &["key/exists"]).generate(),
        ];
        let dispatcher = prepare_vt_storage(&only_success);
        dispatcher
            .dispatch(
                &storage::ContextKey::Scan("sid".into()),
                storage::Field::KB(("key/exists", 1).into()),
            )
            .expect("store kb");
        let result = run(&only_success, dispatcher).expect("success run");
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

    #[test]
    fn mandatory_keys() {
        let only_success = [
            GenerateScript::with_mandatory_keys("0", &["key/not"]).generate(),
            GenerateScript::with_mandatory_keys("1", &["key/exists"]).generate(),
        ];
        let dispatcher = prepare_vt_storage(&only_success);
        dispatcher
            .dispatch(
                &storage::ContextKey::Scan("sid".into()),
                storage::Field::KB(("key/exists", 1).into()),
            )
            .expect("store kb");
        let result = run(&only_success, dispatcher).expect("success run");
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

    #[test]
    fn run_with_schedule() {
        let only_success = [
            GenerateScript::with_dependencies("0", &[]).generate(),
            GenerateScript::with_dependencies("1", &["0.nasl"]).generate(),
            GenerateScript::with_dependencies("2", &["1.nasl"]).generate(),
        ];
        let dispatcher = prepare_vt_storage(&only_success);
        let result = run(&only_success, dispatcher).expect("success");
        let result = result
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.has_succeeded())
            .collect::<Vec<_>>();
        assert_eq!(result.len(), 3);
    }
}
