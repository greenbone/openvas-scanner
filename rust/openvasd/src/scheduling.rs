use std::fmt::Display;

use crate::storage::Error as StorageError;
use async_trait::async_trait;
use models::scanner::Error as ScanError;
use models::scanner::{ScanResultFetcher, ScanResults, ScanStopper};
use models::Phase;
use sysinfo::System;
use tokio::sync::RwLock;

use crate::{
    config,
    controller::ClientHash,
    storage::{AppendFetchResult, NVTStorer, ProgressGetter, ScanIDClientMapper, ScanStorer},
};

#[derive(Debug)]
pub enum Error {
    /// Tried operation that is not allowed while a scan is running
    ScanRunning,
    /// Tried to schedule a scan that is already scheduled
    ScanAlreadyQueued,
    /// Scan to handle is not found in the system
    NotFound,
    /// Queue overseeds the configured maximal queue amount
    QueueFull,
    /// An error occurred while using the Scanner
    Scan(ScanError),
    /// An error occurred while using the DB
    Storage(StorageError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ScanRunning => write!(f, "scan is already running"),
            Error::ScanAlreadyQueued => write!(f, "scan is already queued"),
            Error::NotFound => write!(f, "scan was not found"),
            Error::QueueFull => write!(f, "unable to queue scan: queue is already full."),
            Error::Scan(e) => write!(f, "scan error occurred: {}", e),
            Error::Storage(e) => write!(f, "storage error occurred: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<ScanError> for Error {
    fn from(value: ScanError) -> Self {
        Self::Scan(value)
    }
}

impl From<StorageError> for Error {
    fn from(value: StorageError) -> Self {
        match value {
            StorageError::NotFound => Self::NotFound,
            value => Self::Storage(value),
        }
    }
}

// yo, dawg I heard you like transforming
impl From<Error> for ScanError {
    fn from(val: Error) -> Self {
        ScanError::Unexpected(format!("{}", val))
    }
}
/// Scheduler is a core component of managing scans.
///
/// It follows the scanner traits of models so that a entry point does not have to differentiate
/// between a scanner or scheduler. It additionally provides methods to get running and queued
/// scans. This is necessary to prevent a feed update while a scan is running.
///
/// On scan_start it will queue a scan_id and on run it will verify if necessary resources are
/// available so it can than start the actual scan.
///
/// Additionally it implements all storage traits so that it can be used inside entry without
/// having to store the database double or hide it behind another Arc.
#[derive(Debug)]
pub struct Scheduler<DB, Scanner> {
    /// Contains the currently queued scan ids.
    queued: RwLock<Vec<String>>,
    /// Contains the currently running scan ids.
    running: RwLock<Vec<String>>,
    /// Is used to retrieve scans and update status.
    db: DB,
    /// When true it will prevent starting new scans until the feed got updated
    is_synchronizing_feed: RwLock<bool>,
    /// Is used to start, stop, ... scan.
    scanner: Scanner,
    config: config::Scheduler,
}

impl<DB, Scanner> Scheduler<DB, Scanner> {
    pub fn new(config: config::Scheduler, scanner: Scanner, db: DB) -> Self {
        let assumed_queued = config.max_queued_scans.unwrap_or(10);
        let assumed_running = config.max_running_scans.unwrap_or(10);
        Self {
            queued: RwLock::new(Vec::with_capacity(assumed_queued)),
            running: RwLock::new(Vec::with_capacity(assumed_running)),
            db,
            scanner,
            config,
            is_synchronizing_feed: RwLock::new(false),
        }
    }

    pub fn config(&self) -> &config::Scheduler {
        &self.config
    }
}

impl<DB, Scanner> Scheduler<DB, Scanner>
where
    DB: crate::storage::Storage + Send + Sync + 'static,
    Scanner: models::scanner::Scanner + Send + Sync,
{
    pub async fn start_scan_by_id(&self, id: &str) -> Result<(), Error> {
        let running = self.running.read().await;
        if running.iter().any(|x| x == id) {
            return Err(Error::ScanRunning);
        }
        drop(running);

        let mut status = self.get_status(id).await?;
        status.status = Phase::Requested;
        self.update_status(id, status).await?;

        let mut queued = self.queued.write().await;
        if let Some(max_queuing) = self.config().max_queued_scans {
            if queued.len() == max_queuing {
                return Err(Error::QueueFull);
            }
        }
        if queued.iter().any(|x| x == id) {
            return Err(Error::ScanAlreadyQueued);
        }
        queued.push(id.to_string());
        Ok(())
    }

    pub async fn delete_scan_by_id(&self, id: &str) -> Result<(), Error> {
        let mut queued = self.queued.write().await;
        if let Some(idx) = queued.iter().position(|x| x == id) {
            queued.swap_remove(idx);
        } else {
            let mut running = self.running.write().await;
            if let Some(idx) = running.iter().position(|x| x == id) {
                self.stop_scan(id.to_string()).await?;
                running.swap_remove(idx);
            }
        }
        self.db.remove_scan(id).await?;
        // TODO change from I to &str so that we don't have to clone everywhere
        self.db.remove_scan_id(id.to_string()).await?;
        Ok(())
    }

    /// Coordinates scan starts, if a feed syncrhonization is taking place it will do nothing.
    /// Otherwise it start scans within the capacity block from queued list.
    async fn coordinate_scans(&self) -> Result<(), Error> {
        if *self.is_synchronizing_feed.read().await {
            tracing::debug!("skip scan coordination because a feed synchronization is requested");
            return Ok(());
        }
        let config = self.config();
        let mut queued = self.queued.write().await;
        let mut running = self.running.write().await;
        let amount_to_start = if let Some(mrs) = config.max_running_scans {
            mrs - running.len()
        } else {
            queued.len()
        };
        let mut sys = System::new();

        tracing::debug!(%amount_to_start, "handling scans");
        for _ in 0..amount_to_start {
            if let Some(scan_id) = queued.pop() {
                sys.refresh_memory();
                if let Some(min_free_memory) = self.config.min_free_mem {
                    let available_memory = sys.available_memory();
                    if available_memory < min_free_memory {
                        tracing::debug!(%min_free_memory, %available_memory, %scan_id, "insufficient memory to start scan.");
                    }
                }
                let (scan, status) = self.db.get_decrypted_scan(&scan_id).await?;
                tracing::debug!(?status, %scan_id, "starting scan");

                match self.scanner.start_scan(scan).await {
                    Ok(_) => {
                        tracing::debug!(%scan_id, "started");
                        running.push(scan_id);
                    }
                    Err(ScanError::Connection(e)) => {
                        tracing::warn!(%scan_id, %e, "requeuing because of a connection error");
                        queued.push(scan_id);
                    }
                    Err(e) => {
                        tracing::warn!(%scan_id, %e, "unable to start, removing from queue. Verify that scan using the API");
                    }
                };
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn handle_results(&self) -> Result<(), Error> {
        // we clone to drop the lock
        let running = self.running.read().await.clone();
        for scan_id in running {
            match self.fetch_results(scan_id.clone()).await {
                // using self.append_fetch_result instead of db to keep track of the status
                // and may remove them from running.
                Ok(results) => match self.append_fetched_result(vec![results]).await {
                    Ok(()) => {
                        tracing::trace!(%scan_id, "fetched and append results");
                    }
                    Err(e) => {
                        tracing::warn!(%scan_id, %e, "unable to append results");
                    }
                },
                Err(e) => {
                    tracing::warn!(%scan_id, %e, "unable to fetch results");
                }
            };
        }
        Ok(())
    }

    pub async fn sync_scans(&self) -> Result<(), Error> {
        let coordination = self.coordinate_scans();
        let results = self.handle_results();
        let cr = coordination.await;
        let rr = results.await;
        cr?;
        rr?;
        Ok(())
    }

    pub async fn has_running_scans(&self) -> bool {
        let running = self.running.read().await;
        !running.is_empty()
    }
}

#[async_trait]
impl<DB, Scanner> ScanResultFetcher for Scheduler<DB, Scanner>
where
    DB: crate::storage::Storage + Send + Sync + 'static,
    Scanner: models::scanner::Scanner + Send + Sync,
{
    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.scanner.fetch_results(id).await
    }
}

#[async_trait]
impl<DB, Scanner> ScanStopper for Scheduler<DB, Scanner>
where
    DB: crate::storage::Storage + Send + Sync + 'static,
    Scanner: models::scanner::Scanner + Send + Sync,
{
    async fn stop_scan<I>(&self, id: I) -> Result<(), ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        let cid = id.as_ref().to_string();
        match self.scanner.stop_scan(id).await {
            Ok(_) => {
                let mut queued = self.queued.write().await;
                if let Some(idx) = queued.iter().position(|x| x == &cid) {
                    queued.swap_remove(idx);
                    return Ok(());
                };
                drop(queued);
                let mut running = self.running.write().await;
                if let Some(idx) = running.iter().position(|x| x == &cid) {
                    running.swap_remove(idx);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl<DB, S> ScanIDClientMapper for Scheduler<DB, S>
where
    DB: crate::storage::Storage + Sync + Send + 'static,
    S: Send + Sync,
{
    async fn add_scan_client_id(
        &self,
        scan_id: String,
        client_id: ClientHash,
    ) -> Result<(), StorageError> {
        self.db.add_scan_client_id(scan_id, client_id).await
    }
    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), StorageError>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.db.remove_scan_id(scan_id).await
    }

    async fn get_scans_of_client_id(
        &self,
        client_id: &ClientHash,
    ) -> Result<Vec<String>, StorageError> {
        self.db.get_scans_of_client_id(client_id).await
    }

    async fn is_client_allowed<I>(
        &self,
        scan_id: I,
        client_id: &ClientHash,
    ) -> Result<bool, StorageError>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.db.is_client_allowed(scan_id, client_id).await
    }
}

#[async_trait]
impl<DB, S> ProgressGetter for Scheduler<DB, S>
where
    DB: crate::storage::Storage + Sync + Send + 'static,
    S: Sync + Send,
{
    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), StorageError> {
        self.db.get_scan(id).await
    }
    async fn get_decrypted_scan(
        &self,
        id: &str,
    ) -> Result<(models::Scan, models::Status), StorageError> {
        self.db.get_decrypted_scan(id).await
    }
    async fn get_scan_ids(&self) -> Result<Vec<String>, StorageError> {
        self.db.get_scan_ids().await
    }
    async fn get_status(&self, id: &str) -> Result<models::Status, StorageError> {
        self.db.get_status(id).await
    }
    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, StorageError> {
        self.db.get_results(id, from, to).await
    }
}

#[async_trait]
impl<DB, S> NVTStorer for Scheduler<DB, S>
where
    DB: crate::storage::Storage + Sync + Send + 'static,
    S: Sync + Send,
{
    /// It is marking that a feed synchronization occurs, as long as there are running scans it
    /// will wait until there all scans are finished. In the meantime it will not be possible to
    /// start new scans. This is done to prevent data corruption in a scan process.
    async fn synchronize_feeds(&self, hash: String) -> Result<(), StorageError> {
        let mut sync_feed = self.is_synchronizing_feed.write().await;
        *sync_feed = true;
        let mut interval = tokio::time::interval(self.config().check_interval);
        tracing::debug!("scheduled feed update, blocking starting new scans");
        loop {
            if self.running.read().await.is_empty() {
                break;
            }
            tracing::trace!("blocking until all running scans are finished");
            interval.tick().await;
        }
        let result = match self.db.synchronize_feeds(hash).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        };
        *sync_feed = false;
        tracing::debug!(?result, "feed update finished, scans can be started again");
        result
    }

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, StorageError> {
        self.db.oids().await
    }

    async fn vts<'a>(
        &self,
    ) -> Result<Box<dyn Iterator<Item = storage::item::Nvt> + Send + 'a>, StorageError> {
        self.vts().await
    }

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<storage::item::Nvt>, StorageError> {
        self.db.vt_by_oid(oid).await
    }

    async fn feed_hash(&self) -> String {
        self.db.feed_hash().await
    }
}

#[async_trait]
impl<DB, S> ScanStorer for Scheduler<DB, S>
where
    DB: crate::storage::Storage + Sync + Send + 'static,
    S: Sync + Send,
{
    async fn insert_scan(&self, t: models::Scan) -> Result<(), StorageError> {
        self.db.insert_scan(t).await
    }
    async fn remove_scan(&self, id: &str) -> Result<(), StorageError> {
        self.db.remove_scan(id).await
    }
    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), StorageError> {
        match status.status {
            Phase::Stored | Phase::Requested | Phase::Running => {}
            Phase::Stopped | Phase::Failed | Phase::Succeeded => {
                let mut running = self.running.write().await;
                if let Some(idx) = running.iter().position(|x| x == id) {
                    running.swap_remove(idx);
                }
            }
        };
        self.db.update_status(id, status).await
    }
}

#[async_trait]
impl<DB, S> AppendFetchResult for Scheduler<DB, S>
where
    DB: crate::storage::Storage + Sync + Send + 'static,
    S: Sync + Send,
{
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), StorageError> {
        let mut running = self.running.write().await;
        for x in results.iter() {
            match x.status.status {
                Phase::Stored | Phase::Requested | Phase::Running => {}
                Phase::Stopped | Phase::Failed | Phase::Succeeded => {
                    if let Some(idx) = running.iter().position(|y| y == &x.id) {
                        running.swap_remove(idx);
                    }
                }
            };
        }
        drop(running);
        self.db.append_fetched_result(results).await
    }
}

#[cfg(test)]
mod tests {

    use models::Scan;

    use crate::{
        config,
        scheduling::{self, Scheduler},
        storage::{inmemory, ScanStorer as _},
    };

    mod start {
        use super::*;

        #[tokio::test]
        async fn adds_scan_to_queue() {
            let config = config::Scheduler::default();
            let db = inmemory::Storage::default();
            let scan = Scan::default();
            db.insert_scan(scan.clone()).await.unwrap();
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            scheduler.start_scan_by_id(&scan.scan_id).await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 1);
            assert_eq!(scheduler.running.read().await.len(), 0);
        }
        #[tokio::test]
        async fn error_starting_twice() {
            let config = config::Scheduler::default();
            let db = inmemory::Storage::default();
            let scan = Scan::default();
            db.insert_scan(scan.clone()).await.unwrap();
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            scheduler.start_scan_by_id(&scan.scan_id).await.unwrap();
            assert!(
                match scheduler.start_scan_by_id(&scan.scan_id).await {
                    Err(scheduling::Error::ScanAlreadyQueued) => true,
                    Ok(_) | Err(_) => false,
                },
                "should return a ScanAlreadyQueued"
            );
        }
        #[tokio::test]
        async fn error_not_found() {
            let config = config::Scheduler::default();
            let db = inmemory::Storage::default();
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            assert!(
                match scheduler.start_scan_by_id("1").await {
                    Err(scheduling::Error::NotFound) => true,
                    Ok(_) | Err(_) => false,
                },
                "should return a not found"
            );
        }
        #[tokio::test]
        async fn error_queue_is_full() {
            let mut config = config::Scheduler::default();
            config.max_queued_scans = Some(0);
            let db = inmemory::Storage::default();
            let scan = Scan::default();
            db.insert_scan(scan.clone()).await.unwrap();
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            assert!(
                match scheduler.start_scan_by_id(&scan.scan_id).await {
                    Err(scheduling::Error::QueueFull) => true,
                    Ok(_) | Err(_) => false,
                },
                "should return a QueueFull"
            );
        }
    }
}
