// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

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

    /// Returns true when the Scanner can start a scan.
    async fn can_start_scan(&self, _: &Scan) -> bool {
        true
    }
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

    fn do_addition(&self) -> bool {
        false
    }
}

/// Is a scanner implementation primarily for testing purposes.
///
/// It is holding call back functions so that it is easier to implement a scanner for testing
/// without having to copy and paste the async traits.
#[allow(clippy::complexity)]
pub struct Lambda {
    start: Box<dyn Fn(Scan) -> Result<(), Error> + Sync + Send + 'static>,
    stop: Box<dyn Fn(&str) -> Result<(), Error> + Sync + Send + 'static>,
    delete: Box<dyn Fn(&str) -> Result<(), Error> + Sync + Send + 'static>,
    fetch: Box<dyn Fn(&str) -> Result<ScanResults, Error> + Sync + Send + 'static>,
    can_start: Box<dyn Fn(&Scan) -> bool + Sync + Send + 'static>,
}

impl Default for Lambda {
    fn default() -> Self {
        Self {
            start: Box::new(|_| Ok(())),
            stop: Box::new(|_| Ok(())),
            delete: Box::new(|_| Ok(())),
            fetch: Box::new(|_| Ok(ScanResults::default())),
            can_start: Box::new(|_| true),
        }
    }
}

/// Builds a Lambda scanenr implementation.
///
/// Usage:
/// ```
/// use models::scanner::Error as ScanError;
/// use models::scanner::LambdaBuilder;
///
/// let builder = LambdaBuilder::default().with_start(|_|
/// Err(ScanError::Unexpected("meh".to_string())));
/// let scanner = builder.build();
/// ```
pub struct LambdaBuilder {
    lambda: Lambda,
}

impl Default for LambdaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LambdaBuilder {
    pub fn new() -> Self {
        Self {
            lambda: Lambda::default(),
        }
    }
    pub fn with_start<F>(mut self, f: F) -> Self
    where
        F: Fn(Scan) -> Result<(), Error> + Sync + Send + 'static,
    {
        self.lambda.start = Box::new(f);
        self
    }
    pub fn with_stop<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<(), Error> + Sync + Send + 'static,
    {
        self.lambda.stop = Box::new(f);
        self
    }
    pub fn with_delete<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<(), Error> + Sync + Send + 'static,
    {
        self.lambda.delete = Box::new(f);
        self
    }

    pub fn with_fetch<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<ScanResults, Error> + Sync + Send + 'static,
    {
        self.lambda.fetch = Box::new(f);
        self
    }

    pub fn with_can_start<F>(mut self, f: F) -> Self
    where
        F: Fn(&Scan) -> bool + Sync + Send + 'static,
    {
        self.lambda.can_start = Box::new(f);
        self
    }

    pub fn build(self) -> Lambda {
        self.lambda
    }
}

#[async_trait]
impl ScanStarter for Lambda {
    async fn start_scan(&self, scan: Scan) -> Result<(), Error> {
        (self.start)(scan)
    }

    async fn can_start_scan(&self, scan: &Scan) -> bool {
        (self.can_start)(scan)
    }
}

#[async_trait]
impl ScanStopper for Lambda {
    async fn stop_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        (self.stop)(id.as_ref())
    }
}

#[async_trait]
impl ScanDeleter for Lambda {
    async fn delete_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        (self.delete)(id.as_ref())
    }
}

#[async_trait]
impl ScanResultFetcher for Lambda {
    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        (self.fetch)(id.as_ref())
    }
}

/// Combines all traits needed for a scanner.
#[async_trait]
pub trait Scanner: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher {}

impl<T> Scanner for T where T: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher {}

#[derive(Debug, PartialEq, Eq)]
pub enum ObservableResources {
    CPU,
    Memory,
    IO,
}

impl std::fmt::Display for ObservableResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CPU => write!(f, "CPU"),
            Self::Memory => write!(f, "Memory"),
            Self::IO => write!(f, "IO"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Unexpected(String),
    Connection(String),
    InsufficientResources(Vec<ObservableResources>),
    Poisoned,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unexpected(x) => write!(f, "Unexpecdted issue: {x}"),
            Self::Connection(x) => write!(f, "Connection issue: {x}"),
            Self::InsufficientResources(x) => write!(
                f,
                "Not enough resources of {}",
                x.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            _ => write!(f, "{:?}", self),
        }
    }
}
