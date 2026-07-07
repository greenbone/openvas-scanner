// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//!Contains the scanner implementation for ospd.
//!
//!The scanner is used in openvasd to control scans.
use std::{path::PathBuf, time::Duration};

use crate::{
    scanner::{Error, ScanResults, Scanner},
    utils::scanner_types,
};
use async_trait::async_trait;
use greenbone_scanner_framework::models::Scan;

use super::connection::{delete_scan, get_delete_scan_results, start_scan, stop_scan};

#[derive(Debug, Clone)]
/// OSPD wrapper, is used to utilize ospd
pub struct OspScanner {
    /// Path to the socket
    socket: PathBuf,
    /// Read timeout in seconds
    r_timeout: Option<Duration>,
}

impl OspScanner {
    /// Creates a new instance of OSPDWrapper
    pub fn new(socket: PathBuf, r_timeout: Option<Duration>) -> Self {
        Self { socket, r_timeout }
    }

    fn check_socket(&self) -> Result<PathBuf, Error> {
        if !self.socket.exists() {
            return Err(Error::Unexpected(format!(
                "OSPD socket {} does not exist.",
                self.socket.display()
            )));
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

#[async_trait]
impl Scanner for OspScanner {
    fn scanner_type(&self) -> scanner_types::ScannerType {
        scanner_types::ScannerType::Ospd
    }

    async fn start_scan(&self, scan: Scan) -> Result<(), Error> {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            start_scan(socket, rtimeout, &scan)
                .map(|_| ())
                .map_err(Error::from)
        })
        .await
    }

    async fn stop_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            stop_scan(socket, rtimeout, id)
                .map(|_| ())
                .map_err(Error::from)
        })
        .await
    }

    async fn delete_scan<I>(&self, id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            delete_scan(socket, rtimeout, id)
                .map(|_| ())
                .map_err(Error::from)
        })
        .await
    }

    async fn fetch_results<I>(&self, id: I) -> Result<ScanResults, Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let rtimeout = self.r_timeout;
        self.spawn_blocking(move |socket| {
            get_delete_scan_results(socket, rtimeout, id)
                .map(|r| ScanResults {
                    id: r.clone().id,
                    status: r.clone().into(),
                    results: r.into(),
                })
                .map_err(Error::from)
        })
        .await
    }
}
