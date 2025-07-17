// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Overview of the structure of this module: The `Scanner` is the
//! single instance managing all scans during a run with Openvasd
//! scanner type.  To do so, it starts a number of `RunningScan`s,
//! each of which is responsible for a single Scan.  The `RunningScan`
//! is responsible for computing the execution plan for this
//! particular Scan and running it to completion.  It also takes care
//! of controlling the status of the scan and stopping it if
//! necessary. Internally, it runs code via the `ScanRunner` which is
//! responsible for performing all VTs in all stages on each target
//! host.  It is also responsible for sticking to the scheduling
//! requirements. Finally, for a given VT and a given Host, the
//! VT is then run to completion using the `VTRunner`.

mod error;
pub mod preferences;
mod running_scan;
mod scan;
mod scan_runner;
mod scanner_stack;
mod vt_runner;

#[cfg(test)]
mod tests;

pub use error::ExecuteError;
pub use scan::Scan;
pub use scan_runner::ScanRunner;
pub use scanner_stack::ScannerStack;
pub use scanner_stack::ScannerStackWithStorage;

use async_trait::async_trait;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::sync::RwLock;

use crate::models;
use crate::models::scanner::{
    Error, ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper,
};
use crate::nasl::nasl_std_functions;
use crate::nasl::syntax::{FSPluginLoader, Loader};
use crate::nasl::utils::Executor;
use crate::nasl::utils::scan_ctx::ContextStorage;
use crate::scheduling::SchedulerStorage;
use crate::scheduling::WaveExecutionPlan;
use crate::storage::Remover;
use crate::storage::ScanID;
use crate::storage::inmemory::InMemoryStorage;
use running_scan::{RunningScan, RunningScanHandle};
use scanner_stack::DefaultScannerStack;

/// Allows starting, stopping and managing the results of new scans.
pub struct Scanner<S: ScannerStack> {
    running: Arc<RwLock<HashMap<String, RunningScanHandle>>>,
    storage: Arc<S::Storage>,
    loader: Arc<S::Loader>,
    function_executor: Arc<Executor>,
}

impl<St, L> Scanner<(St, L)>
where
    St: ContextStorage + SchedulerStorage + Sync + Send + Clone + 'static,
    L: Loader + 'static,
{
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
        let storage = Arc::new(InMemoryStorage::new());
        let loader = FSPluginLoader::new(root);
        let executor = nasl_std_functions();
        Self::new(storage, loader, executor)
    }
}

impl<S> Scanner<ScannerStackWithStorage<S>>
where
    S: ContextStorage + SchedulerStorage + Send + Sync + Clone + 'static,
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

impl<S: ScannerStack + 'static> Scanner<S> {
    async fn start_scan_internal(&self, scan: Scan) -> Result<(), Error> {
        let storage = self.storage.clone();
        let loader = self.loader.clone();
        let function_executor = self.function_executor.clone();
        let id = scan.scan_id.clone();
        let handle =
            RunningScan::<S>::start::<WaveExecutionPlan>(scan, storage, loader, function_executor);
        self.running.write().await.insert(id, handle);
        Ok(())
    }
}

#[async_trait]
impl<S: ScannerStack + 'static> ScanStarter for Scanner<S> {
    async fn start_scan(&self, scan: models::Scan) -> Result<(), Error> {
        self.start_scan_internal(Scan::from_resolvable_hosts(scan))
            .await
    }

    async fn can_start_scan(&self, _: &models::Scan) -> bool {
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
            .await
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
        let scan_id = ScanID(id.as_ref().to_string());
        self.stop_scan(id).await?;
        self.storage
            .remove(&scan_id)
            .map_err(|_| Error::ScanNotFound(scan_id.0))?;
        Ok(())
    }
}

#[async_trait]
impl<S: ScannerStack> ScanResultFetcher for Scanner<S> {
    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let id = id.as_ref();
        let running = self.running.read().await;
        let r = running
            .get(id)
            .ok_or_else(|| Error::ScanNotFound(id.to_string()))?;
        let status = r.status().await;
        Ok(ScanResults {
            id: id.to_string(),
            status,
            // TODO: verify
            // The results are directly stored by the storage implementation:
            // inmemory.rs
            // file.rs
            results: vec![],
        })
    }
}
