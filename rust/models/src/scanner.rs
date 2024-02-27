use async_trait::async_trait;

use crate::{Scan, Status};

/// Contains results of a scan as well as identification factors and statuses.
///
/// It is usually returned on fetch_results which gets all results of all running scans for further
/// processing.
#[derive(Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ScanResults {
    pub id: String,
    pub status: Status,
    pub results: Vec<crate::Result>,
}

/// Starts a scan
#[async_trait]
pub trait ScanStarter {
    /// Starts a scan
    async fn start_scan(&self, scan: Scan) -> Result<(), Error>;
}

/// Stops a scan
#[async_trait]
pub trait ScanStopper {
    /// Stops a scan
    async fn stop_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static;
}

/// Deletes a scan
#[async_trait]
pub trait ScanDeleter {
    async fn delete_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static;
}

#[async_trait]
pub trait ScanResultFetcher {
    /// Fetches the results of a scan and combines the results with response
    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, Error>
    where
        I: AsRef<str> + Send + 'static;
}

/// Combines all traits needed for a scanner.
#[async_trait]
pub trait Scanner: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher {}

impl<T> Scanner for T where T: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher {}

#[derive(Debug)]
pub enum Error {
    Unexpected(String),
    Connection(String),
    Poisoned,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unexpected(x) => write!(f, "Unexpecdted issue: {x}"),
            Self::Connection(x) => write!(f, "Connection issue: {x}"),
            _ => write!(f, "{:?}", self),
        }
    }
}
