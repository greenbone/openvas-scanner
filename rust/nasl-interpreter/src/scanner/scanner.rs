use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

use super::{
    running_scan::{RunningScan, RunningScanHandle},
    ScannerStack,
};
use async_trait::async_trait;
use models::{
    scanner::{Error, ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper},
    Scan,
};
use nasl_builtin_utils::Executor;
use nasl_syntax::{FSPluginLoader, Loader};
use storage::{ContextKey, DefaultDispatcher, Storage};

use crate::{
    nasl_std_functions, scheduling::WaveExecutionPlan, DefaultScannerStack, ScannerStackWithStorage,
};

/// Allows starting, stopping and managing the results of new scans.
pub struct Scanner<S: ScannerStack> {
    running: Arc<RwLock<HashMap<String, RunningScanHandle>>>,
    storage: Arc<S::Storage>,
    loader: Arc<S::Loader>,
    function_executor: Arc<Executor>,
}

impl<St, L> Scanner<(St, L)>
where
    St: Storage + Send + 'static,
    L: Loader + Send + 'static,
{
    /// TODO doc
    pub fn new(storage: St, loader: L, executor: Executor) -> Self {
        Self {
            running: Arc::new(RwLock::new(HashMap::default())),
            storage: Arc::new(storage),
            loader: Arc::new(loader),
            function_executor: Arc::new(executor),
        }
    }
}

impl Scanner<DefaultScannerStack> {
    /// Create a new scanner with the default stack.
    /// Requires the root path for the loader.
    pub fn with_default_stack(root: &Path) -> Self {
        let storage = DefaultDispatcher::new();
        let loader = FSPluginLoader::new(root);
        let executor = nasl_std_functions();
        Self::new(storage, loader, executor)
    }
}

impl<S> Scanner<ScannerStackWithStorage<S>>
where
    S: storage::Storage + Send + 'static,
{
    /// Creates a new scanner with a Storage and the rest based on the DefaultScannerStack.
    ///
    /// Requires the root path for the loader and the storage implementation.
    pub fn with_storage(storage: S, root: &Path) -> Self {
        let loader = FSPluginLoader::new(root);
        let executor = nasl_std_functions();
        Self::new(storage, loader, executor)
    }
}

#[async_trait]
impl<S: ScannerStack + 'static> ScanStarter for Scanner<S> {
    async fn start_scan(&self, scan: Scan) -> Result<(), Error> {
        let storage = self.storage.clone();
        let loader = self.loader.clone();
        let function_executor = self.function_executor.clone();
        let id = scan.scan_id.clone();
        let handle =
            RunningScan::<S>::start::<WaveExecutionPlan>(scan, storage, loader, function_executor);
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
        handle.stop();
        Ok(())
    }
}

#[async_trait]
impl<S: ScannerStack> ScanDeleter for Scanner<S> {
    async fn delete_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let ck = ContextKey::Scan(id.as_ref().to_string(), None);
        self.stop_scan(id).await?;
        self.storage
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
                let status = r.status();
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
