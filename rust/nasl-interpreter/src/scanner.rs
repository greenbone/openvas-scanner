use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::SystemTime,
};

use async_trait::async_trait;
use models::{
    scanner::{Error, ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper},
    Scan,
};
use nasl_builtin_utils::{NaslFunctionExecuter, NaslFunctionRegister};
use nasl_syntax::{FSPluginLoader, Loader};
use storage::{DefaultDispatcher, Storage};
use tokio::task::JoinHandle;

use crate::{scheduling::WaveExecutionPlan, SyncScanInterpreter};

struct RunningScan<S: ScannerStack> {
    scan: Scan,
    // Remove mutex to allow parallel usage of those
    storage: Arc<RwLock<S::Storage>>,
    loader: Arc<Mutex<S::Loader>>,
    function_executor: Arc<Mutex<S::Executor>>,
    keep_running: Arc<AtomicBool>,
    status: Arc<RwLock<models::Status>>,
}

fn current_time_in_seconds(name: &'static str) -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(x) => x.as_secs(),
        Err(e) => {
            tracing::warn!(error=?e, name, "unable to get system time, setting defaulting to 0");
            0
        }
    }
}

impl<S: ScannerStack> RunningScan<S> {
    fn set_status_to_running(&self) {
        let mut status = self.status.write().unwrap();
        status.status = models::Phase::Running;
        status.start_time = current_time_in_seconds("start_time").into();
        status.host_info = Some(models::HostInfo {
            all: self.scan.target.hosts.len() as u64,
            // TODO: remove alive and excluded?
            queued: self.scan.target.hosts.len() as u64,
            ..Default::default()
        });
    }

    async fn run<T>(self) -> Result<(), Error>
    where
        T: crate::scheduling::ExecutionPlan,
    {
        // FIXME: based on the lock which is based on a mutex we can just run one scan at a time,
        // the other runs would wait until a lock is freed.
        let storage: &S::Storage = &self.storage.read().unwrap();
        let loader: &S::Loader = &self.loader.lock().unwrap();
        let function_executor: &S::Executor = &self.function_executor.lock().unwrap();
        let interpreter = SyncScanInterpreter::new(storage, loader, function_executor);
        let _span = tracing::error_span!("running", scan = self.scan.scan_id).entered();
        tracing::debug!(scan_id = self.scan.scan_id);
        self.set_status_to_running();
        let mut end_phase = models::Phase::Succeeded;
        let mut last_target = String::new();

        let results = interpreter
            .run::<T>(&self.scan)
            .map(|it| {
                // TODO: check for error and abort, we need to keep track of the state

                for it in it {
                    match it {
                        Ok(x) => {
                            tracing::trace!(last_target, target = x.target, targets=?self.scan.target.hosts);
                            if x.target != last_target {
                                let mut status = self.status.write().unwrap();
                                if let Some(y) = status.host_info.as_mut() {
                                    if y.queued > 0 {
                                        y.queued -= 1;
                                    }
                                    y.finished += 1;
                                    // TODO why is it a hashmap when we return a list of strings
                                    // within the API?
                                    if let Some(scanning) = y.scanning.as_mut() {
                                        scanning.remove(&last_target);

                                        scanning.insert(x.target.clone(), 1);
                                    } else {
                                        let mut current_scan = HashMap::new();
                                        current_scan.insert(x.target.clone(), 1);
                                        y.scanning = Some(current_scan);
                                    }
                                }

                                last_target = x.target.clone();
                            }
                            tracing::debug!(result=?x, "script finished");

                            if x.has_failed() {
                                end_phase = models::Phase::Failed;
                            }
                        }
                        Err(x) => {
                            tracing::warn!(error=?x, "unrecoverable error, aborting whole run");
                            end_phase = models::Phase::Failed;
                        }
                    }
                    if !self.keep_running.load(Ordering::SeqCst) {
                        end_phase = models::Phase::Stopped;
                        break;
                    }
                }
            })
            .map_err(|e| Error::SchedulingError {
                id: self.scan.scan_id.to_string(),
                reason: e.to_string(),
            });

        let mut status = self.status.write().unwrap();
        status.status = end_phase;
        status.end_time = current_time_in_seconds("end_time").into();

        if let Some(hi) = status.host_info.as_mut() {
            hi.scanning = None;
        }
        results
    }
}
struct RunningScanHandle {
    handle: JoinHandle<Result<(), Error>>,
    keep_running: Arc<AtomicBool>,
    status: Arc<RwLock<models::Status>>,
}

impl RunningScanHandle {
    fn start<S, L, N, T>(
        scan: Scan,
        storage: Arc<RwLock<S>>,
        loader: Arc<Mutex<L>>,
        function_executor: Arc<Mutex<N>>,
    ) -> Self
    where
        S: Storage + Send + 'static,
        L: Loader + Send + 'static,
        N: NaslFunctionExecuter + Send + 'static,
        T: crate::scheduling::ExecutionPlan + 'static,
    {
        let keep_running: Arc<AtomicBool> = Arc::new(true.into());
        let status = Arc::new(RwLock::new(models::Status {
            ..Default::default()
        }));
        Self {
            handle: tokio::spawn(
                RunningScan::<(S, L, N)> {
                    scan,
                    storage,
                    loader,
                    function_executor,
                    keep_running: keep_running.clone(),
                    status: status.clone(),
                }
                // TODO run per target
                .run::<T>(),
            ),
            keep_running,
            status,
        }
    }
}

pub trait ScannerStack {
    type Storage: Storage + Sync + Send + 'static;
    type Loader: Loader + Send + 'static;
    type Executor: NaslFunctionExecuter + Send + 'static;
}

impl<S, L, F> ScannerStack for (S, L, F)
where
    S: Storage + Send + 'static,
    L: Loader + Send + 'static,
    F: NaslFunctionExecuter + Send + 'static,
{
    type Storage = S;
    type Loader = L;
    type Executor = F;
}

/// The default scanner stack, consisting of `DefaultDispatcher`,
/// `FSPluginLoader` and `NaslFunctionRegister`.
pub type DefaultScannerStack = (DefaultDispatcher, FSPluginLoader, NaslFunctionRegister);

/// The with storage scanner strack consisting of a statically living sendable Storage
/// implementation,`FSPPluginLoader` nasl `NaslFunctionRegister`.
pub type WithStorageScannerStack<S> = (S, FSPluginLoader, NaslFunctionRegister);

/// Allows starting, stopping and managing the results of new scans.
pub struct Scanner<S: ScannerStack> {
    running: Arc<RwLock<HashMap<String, RunningScanHandle>>>,
    storage: Arc<RwLock<S::Storage>>,
    loader: Arc<Mutex<S::Loader>>,
    function_executor: Arc<Mutex<S::Executor>>,
}

impl<St, L, F> Scanner<(St, L, F)>
where
    St: Storage + Send + 'static,
    L: Loader + Send + 'static,
    F: NaslFunctionExecuter + Send + 'static,
{
    fn new(storage: St, loader: L, executor: F) -> Self {
        Self {
            running: Arc::new(RwLock::new(HashMap::default())),
            storage: Arc::new(RwLock::new(storage)),
            loader: Arc::new(Mutex::new(loader)),
            function_executor: Arc::new(Mutex::new(executor)),
        }
    }
}

impl Scanner<DefaultScannerStack> {
    /// Create a new scanner with the default stack.
    /// Requires the root path for the loader.
    pub fn with_default_stack(root: &Path) -> Self {
        let storage = DefaultDispatcher::new();
        let loader = FSPluginLoader::new(root);
        let executor = crate::nasl_std_functions();
        Self::new(storage, loader, executor)
    }
}

impl<S> Scanner<WithStorageScannerStack<S>>
where
    S: storage::Storage + Send + 'static,
{
    /// Creates a new scanner with a Storage and the rest based on the DefaultScannerStack.
    ///
    /// Requires the root path for the loader and the storage implementation.
    pub fn with_storage(storage: S, root: &Path) -> Self {
        let loader = FSPluginLoader::new(root);
        let executor = crate::nasl_std_functions();
        Self::new(storage, loader, executor)
    }
}

#[async_trait]
impl<S: ScannerStack> ScanStarter for Scanner<S> {
    async fn start_scan(&self, scan: Scan) -> Result<(), Error> {
        let storage = self.storage.clone();
        let loader = self.loader.clone();
        let function_executor = self.function_executor.clone();
        let id = scan.scan_id.clone();
        let handle = RunningScanHandle::start::<_, _, _, WaveExecutionPlan>(
            scan,
            storage,
            loader,
            function_executor,
        );
        self.running.write().unwrap().insert(id, handle);
        Ok(())
    }

    async fn can_start_scan(&self, _: &Scan) -> bool {
        // Todo: Implement this properly
        true
    }
}

#[async_trait]
impl<S: ScannerStack> ScanStopper for Scanner<S> {
    async fn stop_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let id = id.as_ref();
        let handle = self
            .running
            .write()
            .unwrap()
            .remove(id)
            .ok_or_else(|| Error::ScanNotFound(id.to_string()))?;
        handle.keep_running.store(false, Ordering::SeqCst);
        handle.handle.abort();
        Ok(())
    }
}

#[async_trait]
impl<S: ScannerStack> ScanDeleter for Scanner<S> {
    async fn delete_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let ck = storage::ContextKey::Scan(id.as_ref().to_string(), None);
        self.stop_scan(id).await?;
        let store = self.storage.read().unwrap();
        store
            .remove_scan(&ck)
            .map_err(|_| Error::ScanNotFound(ck.as_ref().to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl<S: ScannerStack> ScanResultFetcher for Scanner<S> {
    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let running = self.running.read().unwrap();
        match running.get(id.as_ref()) {
            Some(r) => {
                let status = r.status.read().unwrap().clone();
                Ok(ScanResults {
                    id: id.as_ref().to_string(),
                    status,
                    // The results are directly stored by the storage implementation:
                    // inmemory.rs
                    // file.rs
                    results: vec![],
                })
            }
            None => Err(Error::ScanNotFound(id.as_ref().to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use models::{
        scanner::{ScanResultFetcher, ScanResults, ScanStarter},
        Scan,
    };
    use nasl_builtin_utils::NaslFunctionRegister;
    use storage::item::Nvt;
    use tracing_test::traced_test;

    use crate::{
        scanner::Scanner,
        tests::{setup_success, GenerateScript},
    };

    type TestStack = (
        storage::DefaultDispatcher,
        fn(&str) -> String,
        NaslFunctionRegister,
    );

    fn make_scanner_and_scan_success() -> (Scanner<TestStack>, Scan) {
        let ((storage, loader, executor), scan) = setup_success();
        (Scanner::new(storage, loader, executor), scan)
    }

    fn make_scanner_and_scan(scripts: &[(String, Nvt)]) -> (Scanner<TestStack>, Scan) {
        let ((storage, loader, executor), scan) = crate::tests::setup(scripts);
        (Scanner::new(storage, loader, executor), scan)
    }

    /// Blocks until given id is in given phase or panics after 1 second
    async fn wait_for_status(
        scanner: Scanner<TestStack>,
        id: &str,
        phase: models::Phase,
    ) -> ScanResults {
        let start = super::current_time_in_seconds("test");
        assert!(start > 0);
        loop {
            let current = super::current_time_in_seconds("loop test");
            assert!(
                current > 0,
                "it was not possible to get the system time in seconds"
            );
            assert!(current - start < 1, "time for finishing scan is up.");
            // we need the sloep to not instantly read lock running and preventing write access
            tokio::time::sleep(Duration::from_nanos(100)).await;
            let scan_results = scanner
                .fetch_results(id.to_string())
                .await
                .expect("no error when fetching results");
            tracing::debug!(status=%scan_results.status.status);
            if scan_results.status.status == phase {
                return scan_results;
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
        let res = scanner.start_scan(scan).await;
        assert!(res.is_ok());
        let scan_results = wait_for_status(scanner, &id, models::Phase::Succeeded).await;

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
        scan.target.hosts.push("wald.fee".to_string());

        let id = scan.scan_id.clone();
        let res = scanner.start_scan(scan).await;
        assert!(res.is_ok());
        let scan_results = wait_for_status(scanner, &id, models::Phase::Succeeded).await;

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
}
