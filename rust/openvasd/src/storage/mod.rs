pub mod file;
pub mod inmemory;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

use crate::{controller::ClientHash, crypt, scan::FetchResult};

#[derive(Debug)]
pub enum Error {
    Serialization,
    NotFound,
    Storage(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            NotFound => write!(f, "not found"),
            Serialization => write!(f, "serialization error"),
            Storage(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Serialization
    }
}

impl From<crypt::ParseError> for Error {
    fn from(_: crypt::ParseError) -> Self {
        Self::Serialization
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Self::Serialization
    }
}

#[async_trait]
pub trait ScanIDClientMapper {
    async fn add_scan_client_id(&self, scan_id: String, client_id: ClientHash)
        -> Result<(), Error>;
    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static;

    async fn get_scans_of_client_id(&self, client_id: &ClientHash) -> Result<Vec<String>, Error>;

    async fn is_client_allowed<I>(&self, scan_id: I, client_id: &ClientHash) -> Result<bool, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let scans = self.get_scans_of_client_id(client_id).await?;
        let sid = scan_id.as_ref();
        for id in scans {
            if id == sid {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[async_trait]
/// A trait for getting the progress of a scan, the scan itself with decrypted credentials and
/// encrypted as well as results.
///
/// The main usage of this trait is in the controller and when transforming a scan to a osp
pub trait ProgressGetter {
    /// Returns the scan.
    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error>;
    /// Returns the scan with dcecrypted passwords.
    ///
    /// This method should only be used when the password is required. E.g.
    /// when transforming a scan to a osp command.
    async fn get_decrypted_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error>;
    /// Returns all scans.
    async fn get_scan_ids(&self) -> Result<Vec<String>, Error>;
    /// Returns the status of a scan.
    async fn get_status(&self, id: &str) -> Result<models::Status, Error>;
    /// Returns the results of a scan as json bytes.
    ///
    /// OpenVASD just stores to results without processing them therefore we
    /// can just return the json bytes.
    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error>;
}

#[async_trait]
/// A trait for storing and retrieving oids.
///
/// OIDs are usually retrieved by scanning the feed, although the initial impulse would be to just
/// delete all oids and append new OIDs when finding them. However in a standard scenario the OID
/// list is used to gather capabilities of that particular scanner. To enforce overriding only when
/// all OIDs are gathered it just allows push of all OIDs at once.
pub trait OIDStorer {
    /// Overrides oids
    async fn push_oids(&self, hash: String, oids: Vec<String>) -> Result<(), Error>;

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error>;

    async fn feed_hash(&self) -> String;
}

#[async_trait]
/// A trait for storing scans.
///
/// The main usage of this trait is in the controller and when a user inserts or removes a scan.
pub trait ScanStorer {
    /// Inserts a scan.
    async fn insert_scan(&self, t: models::Scan) -> Result<(), Error>;
    /// Removes a scan.
    async fn remove_scan(&self, id: &str) -> Result<(), Error>;
    /// Updates a status of a scan.
    ///
    /// This is required when a scan is started or stopped.
    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error>;
}

#[async_trait]
/// A trait for appending results from a different source.
///
/// This is used when a scan is started and the results are fetched from ospd.
pub trait AppendFetchResult {
    async fn append_fetched_result(&self, id: &str, results: FetchResult) -> Result<(), Error>;
}

#[async_trait]
/// Combines the traits `ProgressGetter`, `ScanStorer` and `AppendFetchResult`.
pub trait Storage:
    ProgressGetter + ScanStorer + AppendFetchResult + OIDStorer + ScanIDClientMapper
{
}

#[async_trait]
impl<T> Storage for T where
    T: ProgressGetter + ScanStorer + AppendFetchResult + OIDStorer + ScanIDClientMapper
{
}
