//! Application states held by the API.
//!
//! This module contains access points for all stateful operations that either require the
//! [`Feed`] or the [`Scanner`](ScannerBridge) exposed to the API endpoints.
#![allow(clippy::result_large_err)]
use std::sync::{Arc, RwLock, RwLockReadGuard};

use crate::api::error::ApiError;
use crate::container_image_scanner::DBScan;
use crate::database::dao::{DAOError, Execute, Fetch, RetryExec, StreamFetch};
use crate::database::sqlite::results::DBResults;
use crate::database::sqlite::scans::ScanDB;
use crate::scans::scheduling::{self, Message};
use crate::vts::PluginFetcher;
use crate::{crypt::ChaCha20Crypt, database::sqlite::DataBase};

use super::StreamResult;
use futures::{StreamExt, TryStreamExt};
use scannerlib::models::{self, FeedState, Phase, VTData};
use tokio::sync::mpsc::Sender;

/// Feed access point.
#[derive(Clone)]
pub struct Feed {
    /// Storage independent plugin fetcher.
    fetcher: Arc<Box<dyn PluginFetcher + Send + Sync + 'static>>,
    /// Current feed state.
    feed_state: Arc<RwLock<FeedState>>,
}

impl Feed {
    pub fn new<F>(fetcher: F, feed_state: Arc<RwLock<FeedState>>) -> Self
    where
        F: PluginFetcher + Send + Sync + 'static,
    {
        Self {
            fetcher: Arc::new(Box::new(fetcher)),
            feed_state,
        }
    }

    /// Fetches all oids present in the feed and returns it as a JsonStream.
    pub fn get_oids(&self) -> Result<StreamResult<String, ApiError>, ApiError> {
        if matches!(*self.state(), FeedState::Synced(_, _)) {
            Ok(Box::pin(
                self.fetcher
                    .get_oids()
                    .map(|x| x.map_err(ApiError::VtsError)),
            ))
        } else {
            Err(ApiError::FeedNotSynced)
        }
    }

    /// Fetches all vts present in the feed and returns it as a JsonStream.
    pub fn get_vts(&self) -> Result<StreamResult<VTData, ApiError>, ApiError> {
        if matches!(*self.state(), FeedState::Synced(_, _)) {
            Ok(Box::pin(
                self.fetcher
                    .get_vts()
                    .map(|x| x.map_err(ApiError::VtsError)),
            ))
        } else {
            Err(ApiError::FeedNotSynced)
        }
    }

    /// Reads the current feed state.
    pub fn state(&self) -> RwLockReadGuard<'_, FeedState> {
        self.feed_state.read().expect("failed to read feed state")
    }
}

/// Unified bridge between the API and either the container image scanner or normal scanner.
#[derive(Clone)]
pub struct ScannerBridge {
    /// Crypter used to encrypt credentials. Not used by the container image scanner.
    pub crypter: Option<Arc<ChaCha20Crypt>>,
    /// Database to save scan data into.
    pub pool: DataBase,
    /// Scheduler to start or stop scans. Not used by the container image scanner.
    pub scheduler: Option<Sender<Message>>,
}

impl ScannerBridge {
    pub fn new(
        pool: DataBase,
        crypter: Option<Arc<ChaCha20Crypt>>,
        scheduler: Option<Sender<Message>>,
    ) -> Self {
        Self {
            crypter,
            pool,
            scheduler,
        }
    }

    /// Posts a given scan without starting it.
    pub async fn post_scan(&self, client_id: &str, scan: &models::Scan) -> Result<(), DAOError> {
        if let Some(ref crypter) = self.crypter {
            ScanDB::new(&self.pool, (crypter.as_ref(), client_id, scan))
                .exec()
                .await
                .map(|_| ())
        } else {
            DBScan::new(&self.pool, (client_id, scan)).exec().await
        }
    }

    /// Gets all scans owned by the `client_id` and returns a streamed list of their ids.
    pub async fn get_scans(&self, client_id: String) -> StreamResult<String, ApiError> {
        Box::pin(
            if self.crypter.is_some() {
                ScanDB::new(&self.pool, client_id).stream_fetch()
            } else {
                DBScan::new(&self.pool, client_id).stream_fetch()
            }
            .map_err(|e| e.into()),
        )
    }

    /// Gets a scan with a given `scan_id` owned by the client with the given `client_id`.
    pub async fn get_scan(&self, client_id: &str, scan_id: &str) -> Result<models::Scan, ApiError> {
        let id = self.get_scan_id(client_id, scan_id).await?;

        if let Some(ref crypter) = self.crypter {
            ScanDB::new(&self.pool, (crypter.as_ref(), id))
                .fetch()
                .await
        } else {
            DBScan::new(&self.pool, id.to_string()).fetch().await
        }
        .map_err(|e| e.into())
    }

    /// Gets the current status of a scan with a given `scan_id`.
    pub async fn get_scan_status(
        &self,
        client_id: &str,
        scan_id: &str,
    ) -> Result<models::Status, ApiError> {
        let id = self.get_scan_id(client_id, scan_id).await?;

        if self.crypter.is_some() {
            ScanDB::new(&self.pool, id).fetch().await
        } else {
            DBScan::new(&self.pool, id.to_string()).fetch().await
        }
        .map_err(|e| e.into())
    }

    /// Deletes the scan with the given `scan_id` if it is not currently running.
    pub async fn delete_scan(&self, client_id: &str, scan_id: &str) -> Result<(), ApiError> {
        let id = self.get_scan_id(client_id, scan_id).await?.to_string();
        let status = self.get_scan_status(client_id, scan_id).await?;

        if !status.is_running() {
            if self.crypter.is_some() {
                ScanDB::new(&self.pool, id).exec().await?;
            } else {
                DBScan::new(&self.pool, id).retry_exec().await?;
            }
            Ok(())
        } else {
            Err(ApiError::ScanRunning)
        }
    }

    /// Schedules a scan to either stop or start.
    pub async fn schedule_scan(
        &self,
        client_id: &str,
        scan_id: &str,
        action: models::Action,
    ) -> Result<(), ApiError> {
        let id = self.get_scan_id(client_id, scan_id).await?.to_string();
        let status = self.get_scan_status(client_id, scan_id).await?;

        let msg = match action {
            models::Action::Start => match status.status {
                Phase::Succeeded => Err("scan is already completed"),
                Phase::Requested => Err("scan is already requested"),
                Phase::Running => Err("scan is already running"),
                Phase::Failed => Err("scan is already failed"),
                Phase::Stored | Phase::Stopped => Ok(scheduling::Message::Start(id.clone())),
            },
            models::Action::Stop => match status.status {
                Phase::Succeeded => Err("scan is already completed"),
                Phase::Failed => Err("scan is already failed"),
                Phase::Stored | Phase::Stopped => Err("scan is not running"),
                Phase::Requested | Phase::Running => Ok(scheduling::Message::Stop(id.clone())),
            },
        };

        match msg {
            Ok(msg) => {
                if let Some(ref scheduler) = self.scheduler {
                    scheduler.send(msg).await.map_err(|e| e.into())
                } else {
                    DBScan::new(&self.pool, (id, action))
                        .retry_exec()
                        .await
                        .map_err(|e| e.into())
                }
            }
            Err(e) => {
                tracing::warn!(id = scan_id, "{e}");
                Ok(())
            }
        }
    }

    /// Gets a single result from a given scans list of results.
    pub async fn get_scan_result(
        &self,
        client_id: &str,
        scan_id: &str,
        result_id: usize,
    ) -> Result<models::Result, ApiError> {
        let id = self.get_scan_id(client_id, scan_id).await?.to_string();

        DBResults::new(&self.pool, (id, result_id))
            .fetch()
            .await
            .map_err(|e| e.into())
    }

    /// Gets all results of a given scan.
    ///
    /// The results are progressively filled as the scan is running.
    pub async fn get_scan_results(
        &self,
        client_id: &str,
        scan_id: &str,
        start: Option<usize>,
        end: Option<usize>,
    ) -> Result<StreamResult<models::Result, ApiError>, ApiError> {
        let id = self.get_scan_id(client_id, scan_id).await?.to_string();

        let results = DBResults::new(&self.pool, (id, start, end))
            .stream_fetch()
            .map_err(|e| e.into());
        Ok(Box::pin(results))
    }

    /// Helper function to resolve a `client_id` and `scan_id` to the scans internal id.
    pub async fn get_scan_id(&self, client_id: &str, scan_id: &str) -> Result<i64, ApiError> {
        Ok(ScanDB::new(&self.pool, (client_id, scan_id))
            .fetch()
            .await?
            .ok_or(DAOError::NotFound)?
            .parse::<i64>()
            .expect("numeric ID"))
    }
}
