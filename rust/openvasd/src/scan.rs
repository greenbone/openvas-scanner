// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{path::PathBuf, sync::PoisonError, time::Duration};

use async_trait::async_trait;

/// The result of a fetch operation
pub type FetchResult = (models::Status, Vec<models::Result>);

impl From<osp::Error> for Error {
    fn from(value: osp::Error) -> Self {
        Self::Unexpected(format!("{value:?}"))
    }
}

#[derive(Debug, Clone)]
/// OSPD wrapper, is used to utilize ospd
pub struct OSPDWrapper {
    /// Path to the socket
    socket: PathBuf,
    /// Read timeout in seconds
    r_timeout: Option<Duration>,
}

#[derive(Debug)]
pub enum Error {
    Unexpected(String),
    SocketDoesNotExist(PathBuf),
    Poisoned,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketDoesNotExist(p) => {
                write!(f, "The OSPD socket {} does not exist", p.display())
            }
            _ => write!(f, "{:?}", self),
        }
    }
}

impl From<crate::storage::Error> for Error {
    fn from(value: crate::storage::Error) -> Self {
        Self::Unexpected(format!("{value:?}"))
    }
}
impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Self::Poisoned
    }
}

impl OSPDWrapper {
    /// Creates a new instance of OSPDWrapper
    pub fn new(socket: PathBuf, r_timeout: Option<Duration>) -> Self {
        Self { socket, r_timeout }
    }

    fn check_socket(&self) -> Result<PathBuf, Error> {
        if !self.socket.exists() {
            return Err(Error::SocketDoesNotExist(self.socket.clone()));
        }
        Ok(self.socket.clone())
    }
    async fn spawn_blocking<F, R, E>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(PathBuf) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: Into<Error> + Send + 'static,
    {
        let socket = self.check_socket()?;
        tokio::task::spawn_blocking(move || f(socket).map_err(Into::into))
            .await
            .map_err(|_| Error::Poisoned)?
    }
}

/// Starts a scan
#[async_trait]
pub trait ScanStarter {
    /// Starts a scan
    async fn start_scan(&self, scan: models::Scan) -> Result<(), Error>;
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
    async fn fetch_results<I>(&self, id: I) -> Result<FetchResult, Error>
    where
        I: AsRef<str> + Send + 'static;
}

#[async_trait]
impl ScanStarter for OSPDWrapper {
    async fn start_scan(&self, scan: models::Scan) -> Result<(), Error> {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            osp::start_scan(socket, rtimeout, &scan)
                .map(|_| ())
                .map_err(Error::from)
        })
        .await
    }
}

#[async_trait]
impl ScanStopper for OSPDWrapper {
    async fn stop_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            osp::stop_scan(socket, rtimeout, id)
                .map(|_| ())
                .map_err(Error::from)
        })
        .await
    }
}

#[async_trait]
impl ScanDeleter for OSPDWrapper {
    async fn delete_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            osp::delete_scan(socket, rtimeout, id)
                .map(|_| ())
                .map_err(Error::from)
        })
        .await
    }
}

#[async_trait]
impl ScanResultFetcher for OSPDWrapper {
    async fn fetch_results<I>(&self, id: I) -> Result<FetchResult, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            osp::get_delete_scan_results(socket, rtimeout, id)
                .map(|r| (r.clone().into(), r.into()))
                .map_err(Error::from)
        })
        .await
    }
}
