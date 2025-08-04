// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use async_trait::async_trait;
use models::NotusResults;
use scannerlib::{
    models,
    notus::{HashsumProductLoader, Notus, NotusError},
};
use tokio::sync::RwLock;

#[async_trait]
pub trait NotusScanner {
    async fn scan(&self, os: &str, packages: &[String]) -> Result<NotusResults, NotusError>;
    async fn get_available_os(&self) -> Result<Vec<String>, NotusError>;
}

#[derive(Debug)]
pub struct NotusWrapper {
    notus: RwLock<Notus<HashsumProductLoader>>,
}

impl NotusWrapper {
    pub fn new(notus: Notus<HashsumProductLoader>) -> Self {
        Self {
            notus: RwLock::new(notus),
        }
    }
}

#[async_trait]
impl NotusScanner for NotusWrapper {
    async fn scan(&self, os: &str, packages: &[String]) -> Result<NotusResults, NotusError> {
        self.notus.write().await.scan(os, packages)
    }

    async fn get_available_os(&self) -> Result<Vec<String>, NotusError> {
        self.notus.read().await.get_available_os()
    }
}
