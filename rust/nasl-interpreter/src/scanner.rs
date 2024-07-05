use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
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
    storage: Arc<Mutex<S::Storage>>,
    loader: Arc<Mutex<S::Loader>>,
    function_executor: Arc<Mutex<S::Executor>>,
    keep_running: Arc<AtomicBool>,
}

impl<S: ScannerStack> RunningScan<S> {
    async fn run(self) -> Result<(), Error> {
        let storage: &S::Storage = &self.storage.lock().unwrap();
        let loader: &S::Loader = &self.loader.lock().unwrap();
        let function_executor: &S::Executor = &self.function_executor.lock().unwrap();
        let interpreter = SyncScanInterpreter::new(storage, loader, function_executor);
        interpreter
            // Todo: Make this generic over the scheduler
            .run::<WaveExecutionPlan>(&self.scan)
            .map(|it| {
                for _ in it {
                    if !self.keep_running.load(Ordering::SeqCst) {
                        break;
                    }
                }
            })
            .map_err(|_|
                     // Todo: proper error handling
                     Error::Poisoned)
    }
}

struct RunningScanHandle {
    handle: JoinHandle<Result<(), Error>>,
    keep_running: Arc<AtomicBool>,
}

impl RunningScanHandle {
    fn start<S, L, N>(
        scan: Scan,
        storage: Arc<Mutex<S>>,
        loader: Arc<Mutex<L>>,
        function_executor: Arc<Mutex<N>>,
    ) -> Self
    where
        S: Storage + Send + 'static,
        L: Loader + Send + 'static,
        N: NaslFunctionExecuter + Send + 'static,
    {
        let keep_running: Arc<AtomicBool> = Arc::new(true.into());
        Self {
            handle: tokio::spawn(
                RunningScan::<(S, L, N)> {
                    scan,
                    storage,
                    loader,
                    function_executor,
                    keep_running: keep_running.clone(),
                }
                .run(),
            ),
            keep_running,
        }
    }
}

pub trait ScannerStack {
    type Storage: Storage + Send + 'static;
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

/// Allows starting, stopping and managing the results of new scans.
pub struct Scanner<S: ScannerStack> {
    running: Arc<Mutex<HashMap<String, RunningScanHandle>>>,
    storage: Arc<Mutex<S::Storage>>,
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
            running: Arc::new(Mutex::new(HashMap::default())),
            storage: Arc::new(Mutex::new(storage)),
            loader: Arc::new(Mutex::new(loader)),
            function_executor: Arc::new(Mutex::new(executor)),
        }
    }
}

impl Scanner<DefaultScannerStack> {
    /// Create a new scanner with the default stack.
    /// Requires the root path for the loader.
    pub fn with_default_stack(root: &Path) -> Self {
        let storage = DefaultDispatcher::new(true);
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
        let handle = RunningScanHandle::start(scan, storage, loader, function_executor);
        self.running.lock().unwrap().insert(id, handle);
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
            .lock()
            .unwrap()
            .remove(id)
            // TODO: Do this properly
            .ok_or_else(|| Error::Unexpected(id.to_string()))?;
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
        self.stop_scan(id).await?;
        // TODO: Delete the results
        todo!()
    }
}

#[async_trait]
impl<S: ScannerStack> ScanResultFetcher for Scanner<S> {
    async fn fetch_results<I>(&self, _id: I) -> Result<ScanResults, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use models::{scanner::ScanStarter, Scan};
    use nasl_builtin_utils::NaslFunctionRegister;

    use crate::{scanner::Scanner, tests::setup};

    fn make_scanner_and_scan() -> (
        Scanner<(
            storage::DefaultDispatcher,
            fn(&str) -> String,
            NaslFunctionRegister,
        )>,
        Scan,
    ) {
        let ((storage, loader, executor), scan) = setup();
        (Scanner::new(storage, loader, executor), scan)
    }

    #[tokio::test]
    async fn start_scan() {
        let (scanner, scan) = make_scanner_and_scan();
        let res = scanner.start_scan(scan).await;
        assert!(res.is_ok());
    }
}
