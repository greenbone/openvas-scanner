// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! scan-interpreter interprets models::Scan

use nasl_builtin_utils::NaslFunctionExecuter;
use nasl_syntax::{
    logger::{DefaultLogger, NaslLogger},
    Loader, NaslValue,
};
use storage::{ContextKey, Storage};

use crate::{scheduling::ExecutionPlaner, InterpretError};

/// Runs a scan in a synchronous mode
///
/// As a Scan is able to configure the behavior of scripts (e.g. consider_alive means that each
/// port within the scan is considered reachable without testing) each Interpreter must be created
/// for each scan and is not reusable.
pub struct SyncScanInterpreter<'a, S, L, N> {
    storage: &'a S,
    loader: &'a L,
    logger: DefaultLogger,
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
#[derive(Debug)]
/// Contains the result of a executed script
pub enum ScriptResultKind {
    /// Contains the code provided by exit call or 0 when script finished successful without exit
    /// call
    ReturnCode(i64),
    /// Contains the error the script returned
    Error(InterpretError),
}

#[derive(Debug)]
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
    pub fn is_success(&self) -> bool {
        matches!(&self.kind, ScriptResultKind::ReturnCode(0))
    }
}

struct ScriptExecutor<'a, T> {
    schedule: T,
    scan: &'a models::Scan,

    /// Default Retriever
    storage: &'a dyn Storage,
    /// Default Loader
    loader: &'a dyn Loader,
    // TODO remove logger in favor of tracing
    /// Default logger.
    logger: &'a dyn NaslLogger,
    /// Default logger.
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
        logger: &'a DefaultLogger,
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
            logger,
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

        let context = crate::Context::new(
            ContextKey::Scan(self.scan.scan_id.clone()),
            target,
            self.storage.as_dispatcher(),
            self.storage.as_retriever(),
            self.loader,
            self.logger,
            self.executor,
        );
        let mut interpret = crate::CodeInterpreter::new(&code, register, &context);
        tracing::debug!("running");
        let kind = interpret
            .find_map(|r| match r {
                Ok(NaslValue::Exit(x)) => Some(ScriptResultKind::ReturnCode(x)),
                Err(e) => Some(ScriptResultKind::Error(e.clone())),
                Ok(x) => {
                    tracing::trace!(statement_result=?x);
                    None
                }
            })
            .unwrap_or_else(|| ScriptResultKind::ReturnCode(0));
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
            logger: nasl_syntax::logger::DefaultLogger::default(),
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
            // hiding logger implementation as we want to replace it with tracing
            logger: nasl_syntax::logger::DefaultLogger::default(),
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
            &self.logger,
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

    fn create_script(id: &str, rc: usize, dependencies: &[&str]) -> (String, storage::item::Nvt) {
        let mut dependencies = dependencies.iter().fold(String::default(), |acc, e| {
            let acc = if acc.is_empty() {
                acc
            } else {
                format!("{acc}, ")
            };
            format!("\"{acc}{e}.nasl\"")
        });
        if !dependencies.is_empty() {
            dependencies = format!("script_dependencies({})", dependencies);
        }
        let code = format!(
            r#"
if (description)
{{
  script_oid("{id}");
  script_category(ACT_GATHER_INFO);
  {dependencies};
  exit(0);
}}
exit({rc});
"#
        );
        let nvt = storage::item::Nvt {
            oid: id.to_string(),
            filename: format!("{id}.nasl"),
            category: nasl_syntax::ACT::GatherInfo,
            ..Default::default()
        };
        (code, nvt)
    }

    #[test]
    fn run_with_schedule() {
        let only_success = [
            create_script("0", 0, &[]),
            create_script("1", 0, &["0"]),
            create_script("2", 0, &["1"]),
        ];
        use storage::Dispatcher;
        let dispatcher = storage::DefaultDispatcher::new(true);
        only_success.iter().map(|(_, v)| v).for_each(|n| {
            dispatcher
                .dispatch(
                    &storage::ContextKey::FileName(n.filename.clone()),
                    storage::Field::NVT(storage::item::NVTField::Nvt(n.clone())),
                )
                .expect("sending")
        });
        let stou = |s: &str| s.split('.').next().unwrap().parse::<usize>().unwrap();
        let loader = |s: &str| only_success[stou(s)].0.clone();
        let scan = models::Scan {
            scan_id: "sid".to_string(),
            target: models::Target {
                hosts: vec!["test.host".to_string()],
                ..Default::default()
            },
            scan_preferences: vec![],
            vts: only_success
                .iter()
                .map(|(_, v)| models::VT {
                    oid: v.oid.clone(),
                    parameters: vec![],
                })
                .collect(),
        };
        let interpreter =
            super::SyncScanInterpreter::with_default_function_executor(&dispatcher, &loader);
        let result = interpreter
            .run::<crate::scheduling::WaveExecutionPlan>(&scan)
            .expect("success")
            .filter_map(|x| x.ok())
            .filter(|x| x.is_success())
            .collect::<Vec<_>>();
        assert_eq!(result.len(), 3);
    }
}
