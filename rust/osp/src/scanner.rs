// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//!Contains the scanner implementation for ospd.
//!
//!The scanner is used in openvasd to control scans.
use std::{path::PathBuf, time::Duration};

use async_trait::async_trait;
use models::scanner::{ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper};

#[derive(Debug, Clone)]
/// OSPD wrapper, is used to utilize ospd
pub struct Scanner {
    /// Path to the socket
    socket: PathBuf,
    /// Read timeout in seconds
    r_timeout: Option<Duration>,
}

impl Scanner {
    /// Creates a new instance of OSPDWrapper
    pub fn new(socket: PathBuf, r_timeout: Option<Duration>) -> Self {
        Self { socket, r_timeout }
    }

    fn check_socket(&self) -> Result<PathBuf, models::scanner::Error> {
        if !self.socket.exists() {
            return Err(models::scanner::Error::Unexpected(format!(
                "OSPD socket {} does not exist.",
                self.socket.display()
            )));
        }
        Ok(self.socket.clone())
    }
    async fn spawn_blocking<F, R, E>(&self, f: F) -> Result<R, models::scanner::Error>
    where
        F: FnOnce(PathBuf) -> Result<R, E> + Send + 'static,
        R: Send + 'static,
        E: Into<models::scanner::Error> + Send + 'static,
    {
        let socket = self.check_socket()?;
        tokio::task::spawn_blocking(move || f(socket).map_err(Into::into))
            .await
            .map_err(|_| models::scanner::Error::Poisoned)?
    }
}

#[async_trait]
impl ScanStarter for Scanner {
    async fn start_scan(&self, scan: models::Scan) -> Result<(), models::scanner::Error> {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            crate::start_scan(socket, rtimeout, &scan)
                .map(|_| ())
                .map_err(models::scanner::Error::from)
        })
        .await
    }

    async fn can_start_scan(&self, _: &models::Scan) -> bool {
        true
    }
}

#[async_trait]
impl ScanStopper for Scanner {
    async fn stop_scan<I>(&self, id: I) -> Result<(), models::scanner::Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            crate::stop_scan(socket, rtimeout, id)
                .map(|_| ())
                .map_err(models::scanner::Error::from)
        })
        .await
    }
}

#[async_trait]
impl ScanDeleter for Scanner {
    async fn delete_scan<I>(&self, id: I) -> Result<(), models::scanner::Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            crate::delete_scan(socket, rtimeout, id)
                .map(|_| ())
                .map_err(models::scanner::Error::from)
        })
        .await
    }
}

#[async_trait]
impl ScanResultFetcher for Scanner {
    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, models::scanner::Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            crate::get_delete_scan_results(socket, rtimeout, id)
                .map(|r| ScanResults {
                    id: r.clone().id,
                    status: r.clone().into(),
                    results: r.into(),
                })
                .map_err(models::scanner::Error::from)
        })
        .await
    }
}
