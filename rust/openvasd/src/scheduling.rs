// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::Display;
use std::time::SystemTime;

use crate::storage::{Error as StorageError, FeedHash};
use async_trait::async_trait;
use models::scanner::Error as ScanError;
use models::scanner::{ScanResultFetcher, ScanResults, ScanStopper};
use models::Phase;
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
    /// Unsupported resume
    UnsupportedResume,
    /// A scan ins already finished
    AlreadyFinished,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ScanRunning => write!(f, "scan is already running"),
            Error::ScanAlreadyQueued => write!(f, "scan is already queued"),
            Error::NotFound => write!(f, "scan was not found"),
            Error::QueueFull => write!(f, "unable to queue scan: queue is already full"),
            Error::Scan(e) => write!(f, "scan error occurred: {}", e),
            Error::Storage(e) => write!(f, "storage error occurred: {}", e),
            Error::UnsupportedResume => {
                write!(f, "unable to resume scan: operation not supported")
            }
            Error::AlreadyFinished => write!(f, "unable to resume scan: scan already finished"),
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
        match status.status {
            Phase::Stored => status.status = Phase::Requested,
            Phase::Requested => return Err(Error::ScanAlreadyQueued),
            Phase::Running => return Err(Error::ScanRunning),
            Phase::Stopped | Phase::Failed => return Err(Error::UnsupportedResume),
            Phase::Succeeded => return Err(Error::AlreadyFinished),
        }

        let mut queued = self.queued.write().await;
        if let Some(max_queuing) = self.config().max_queued_scans {
            if queued.len() == max_queuing {
                return Err(Error::QueueFull);
            }
        }
        if queued.iter().any(|x| x == id) {
            return Err(Error::ScanAlreadyQueued);
        }
        self.update_status(id, status).await?;
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
                self.scanner.stop_scan(id.to_string()).await?;
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

        tracing::trace!(%amount_to_start, "handling scans");
        for _ in 0..amount_to_start {
            if let Some(scan_id) = queued.pop() {
                let (scan, status) = self.db.get_decrypted_scan(&scan_id).await?;
                if !self.scanner.can_start_scan(&scan).await {
                    tracing::debug!(?status, %scan_id, "unable to start scan");
                    queued.push(scan_id);
                } else {
                    tracing::debug!(?status, %scan_id, "starting scan");
                    match self.scanner.start_scan(scan).await {
                        Ok(_) => {
                            tracing::debug!(%scan_id, "started");
                            running.push(scan_id.clone());
                        }
                        Err(ScanError::Connection(e)) => {
                            tracing::warn!(%scan_id, %e, "requeuing because of a connection error");
                            queued.push(scan_id);
                        }
                        Err(e) => {
                            tracing::warn!(%scan_id, %e, "unable to start, removing from queue and set status to failed. Verify that scan using the API");
                            self.db
                                .update_status(
                                    &scan_id,
                                    models::Status {
                                        start_time: None,
                                        end_time: None,
                                        status: Phase::Failed,
                                        host_info: None,
                                    },
                                )
                                .await?;
                        }
                    };
                }
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
                Ok(mut results) => {
                    if self.scanner.do_addition() {
                        let scan_status = self.db.get_status(&scan_id).await?;
                        let current_hosts_status = scan_status.host_info.unwrap_or_default();
                        let mut new_status = results.status.host_info.unwrap_or_default();
                        // total hosts value is sent once and only once must be updated
                        if current_hosts_status.all != 0 {
                            new_status.all = current_hosts_status.all;
                        }
                        // excluded hosts value is sent once and only once must be updated
                        if new_status.excluded == 0 {
                            new_status.excluded = current_hosts_status.excluded;
                        }
                        // new dead/alive/finished hosts are found during the scan.
                        // the new count must be added to the previous one
                        new_status.dead += current_hosts_status.dead;
                        new_status.alive += current_hosts_status.alive;
                        new_status.finished += current_hosts_status.finished;

                        //Update each single host status. Remove it if finished.
                        let mut hs = current_hosts_status.scanning.unwrap_or_default().clone();
                        for (host, progress) in
                            new_status.scanning.clone().unwrap_or_default().iter()
                        {
                            if *progress == 100 || *progress == -1 {
                                hs.remove(host);
                            } else {
                                hs.insert(host.to_string(), *progress);
                            }
                        }
                        new_status.scanning = Some(hs);

                        // update the hosts stauts into the result before storing
                        results.status.host_info = Some(new_status);

                        // Update start and end time if set from openvas
                        if scan_status.start_time.is_some() {
                            results.status.start_time = scan_status.start_time;
                        }

                        if scan_status.end_time.is_some() {
                            results.status.end_time = scan_status.end_time;
                        }

                        match self.append_fetched_result(vec![results]).await {
                            Ok(()) => {
                                tracing::trace!(%scan_id, "fetched and append results");
                            }
                            Err(e) => {
                                tracing::warn!(%scan_id, %e, "unable to append results");
                            }
                        };
                    } else {
                        match self.append_fetched_result(vec![results]).await {
                            Ok(()) => {
                                tracing::trace!(%scan_id, "fetched and append results");
                            }
                            Err(e) => {
                                tracing::warn!(%scan_id, %e, "unable to append results");
                            }
                        }
                    }
                }
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
        self.scanner.stop_scan(id).await?;
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
        let mut current_status = self.db.get_status(&cid).await?;
        current_status.status = Phase::Stopped;
        current_status.end_time = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Valid timestamp for end scan")
                .as_secs() as u32,
        );

        self.db.update_status(&cid, current_status).await?;
        Ok(())
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
    async fn synchronize_feeds(
        &self,
        hash: Vec<crate::storage::FeedHash>,
    ) -> Result<(), StorageError> {
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
        self.db.vts().await
    }

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<storage::item::Nvt>, StorageError> {
        self.db.vt_by_oid(oid).await
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.db.feed_hash().await.to_vec()
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
    use tracing_test::traced_test;

    use models::Scan;

    use crate::{
        config,
        scheduling::{self, Scheduler},
        storage::{inmemory, ScanStorer as _},
    };

    mod synchronize {
        use models::scanner::ScanStopper as _;

        use super::*;

        #[traced_test]
        #[tokio::test]
        async fn set_running() {
            let scans = std::iter::repeat(Scan::default())
                .take(10)
                .map(|x| {
                    let mut y = x.clone();
                    y.scan_id = uuid::Uuid::new_v4().to_string();
                    y
                })
                .collect::<Vec<_>>();
            let config = config::Scheduler::default();
            let db = inmemory::Storage::default();
            for s in scans.clone().into_iter() {
                db.insert_scan(s).await.unwrap();
            }
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            for s in scans {
                scheduler.start_scan_by_id(&s.scan_id).await.unwrap();
            }
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 0);
            assert_eq!(scheduler.running.read().await.len(), 10);
        }

        #[traced_test]
        #[tokio::test]
        async fn not_move_from_queue_on_max_running() {
            let scans = std::iter::repeat(Scan::default())
                .take(10)
                .map(|x| {
                    let mut y = x.clone();
                    y.scan_id = uuid::Uuid::new_v4().to_string();
                    y
                })
                .collect::<Vec<_>>();
            let config = config::Scheduler {
                max_running_scans: Some(5),
                ..Default::default()
            };
            let db = inmemory::Storage::default();
            for s in scans.clone().into_iter() {
                db.insert_scan(s).await.unwrap();
            }
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            for s in scans {
                scheduler.start_scan_by_id(&s.scan_id).await.unwrap();
            }
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 5);
            assert_eq!(scheduler.running.read().await.len(), 5);
            // no change
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 5);
            assert_eq!(scheduler.running.read().await.len(), 5);
            scheduler.running.write().await.clear();
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 0);
            assert_eq!(scheduler.running.read().await.len(), 5);
        }
        #[traced_test]
        #[tokio::test]
        async fn not_move_from_queue_on_insufficient_memory() {
            let scans = std::iter::repeat(Scan::default())
                .take(10)
                .map(|x| {
                    let mut y = x.clone();
                    y.scan_id = uuid::Uuid::new_v4().to_string();
                    y
                })
                .collect::<Vec<_>>();
            let config = config::Scheduler::default();

            let db = inmemory::Storage::default();
            for s in scans.clone().into_iter() {
                db.insert_scan(s).await.unwrap();
            }
            let scanner = models::scanner::LambdaBuilder::new()
                .with_can_start(|_| false)
                .build();
            let scheduler = Scheduler::new(config, scanner, db);
            for s in scans {
                scheduler.start_scan_by_id(&s.scan_id).await.unwrap();
            }
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 10);
            assert_eq!(scheduler.running.read().await.len(), 0);
        }

        #[traced_test]
        #[tokio::test]
        async fn not_move_from_queue_on_connection_error() {
            let scans = std::iter::repeat(Scan::default())
                .take(10)
                .map(|x| {
                    let mut y = x.clone();
                    y.scan_id = uuid::Uuid::new_v4().to_string();
                    y
                })
                .collect::<Vec<_>>();
            let config = config::Scheduler::default();

            let db = inmemory::Storage::default();
            for s in scans.clone().into_iter() {
                db.insert_scan(s).await.unwrap();
            }
            let scanner = models::scanner::LambdaBuilder::new()
                .with_start(|_| Err(models::scanner::Error::Connection("m".to_string())))
                .build();
            let scheduler = Scheduler::new(config, scanner, db);
            for s in scans {
                scheduler.start_scan_by_id(&s.scan_id).await.unwrap();
            }
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 10);
            assert_eq!(scheduler.running.read().await.len(), 0);
        }

        #[traced_test]
        #[tokio::test]
        async fn remove_from_queue_on_any_other_scan_error() {
            let scans = std::iter::repeat(Scan::default())
                .take(10)
                .map(|x| {
                    let mut y = x.clone();
                    y.scan_id = uuid::Uuid::new_v4().to_string();
                    y
                })
                .collect::<Vec<_>>();
            let config = config::Scheduler::default();

            let db = inmemory::Storage::default();
            for s in scans.clone().into_iter() {
                db.insert_scan(s).await.unwrap();
            }
            let scanner = models::scanner::LambdaBuilder::new()
                .with_start(|_| Err(models::scanner::Error::Unexpected("m".to_string())))
                .build();
            let scheduler = Scheduler::new(config, scanner, db);
            for s in scans {
                scheduler.start_scan_by_id(&s.scan_id).await.unwrap();
            }
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 0);
            assert_eq!(scheduler.running.read().await.len(), 0);
        }

        #[traced_test]
        #[tokio::test]
        async fn remove_from_running_when_stop() {
            let scans = std::iter::repeat(Scan::default())
                .take(10)
                .map(|x| {
                    let mut y = x.clone();
                    y.scan_id = uuid::Uuid::new_v4().to_string();
                    y
                })
                .collect::<Vec<_>>();
            let config = config::Scheduler::default();
            let db = inmemory::Storage::default();
            for s in scans.clone().into_iter() {
                db.insert_scan(s).await.unwrap();
            }
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            for s in scans.iter() {
                scheduler.start_scan_by_id(&s.scan_id).await.unwrap();
            }
            scheduler.sync_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 0);
            assert_eq!(scheduler.running.read().await.len(), 10);
            for s in scans {
                scheduler.stop_scan(s.scan_id).await.unwrap();
            }
            assert_eq!(scheduler.queued.read().await.len(), 0);
            assert_eq!(scheduler.running.read().await.len(), 0);
        }
        #[traced_test]
        #[tokio::test]
        async fn remove_from_running_when_finished() {
            let scans = std::iter::repeat(Scan::default())
                .take(10)
                .map(|x| {
                    let mut y = x.clone();
                    y.scan_id = uuid::Uuid::new_v4().to_string();
                    y
                })
                .collect::<Vec<_>>();
            let config = config::Scheduler::default();
            let db = inmemory::Storage::default();
            for s in scans.clone().into_iter() {
                db.insert_scan(s).await.unwrap();
            }
            let scanner = models::scanner::LambdaBuilder::default()
                .with_fetch(|s| {
                    Ok(models::scanner::ScanResults {
                        id: s.to_string(),
                        status: models::Status {
                            start_time: None,
                            end_time: None,
                            status: models::Phase::Succeeded,
                            host_info: None,
                        },
                        results: vec![],
                    })
                })
                .build();
            let scheduler = Scheduler::new(config, scanner, db);
            for s in scans.iter() {
                scheduler.start_scan_by_id(&s.scan_id).await.unwrap();
            }
            // we cannot use overall sync as it does result fetching
            //scheduler.sync_scans().await.unwrap();
            scheduler.coordinate_scans().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 0);
            assert_eq!(scheduler.running.read().await.len(), 10);
            scheduler.handle_results().await.unwrap();
            assert_eq!(scheduler.queued.read().await.len(), 0);
            assert_eq!(scheduler.running.read().await.len(), 0);
        }
    }

    mod start {
        use crate::storage::ProgressGetter;

        use super::*;

        #[traced_test]
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
        #[traced_test]
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
        #[traced_test]
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
        #[traced_test]
        #[tokio::test]
        async fn error_queue_is_full() {
            let config = config::Scheduler {
                max_queued_scans: Some(0),
                ..Default::default()
            };
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
        #[traced_test]
        #[tokio::test]
        async fn error_resume_unsupported() {
            let config = config::Scheduler {
                max_queued_scans: Some(0),
                ..Default::default()
            };
            let db = inmemory::Storage::default();
            let scan = Scan::default();
            db.insert_scan(scan.clone()).await.unwrap();
            let mut status = db.get_status("").await.unwrap();
            status.status = models::Phase::Failed;
            db.update_status("", status).await.unwrap();
            let scanner = models::scanner::Lambda::default();
            let scheduler = Scheduler::new(config, scanner, db);
            assert!(
                match scheduler.start_scan_by_id(&scan.scan_id).await {
                    Err(scheduling::Error::UnsupportedResume) => true,
                    Ok(_) | Err(_) => false,
                },
                "should return a QueueFull"
            );
        }
    }
}
