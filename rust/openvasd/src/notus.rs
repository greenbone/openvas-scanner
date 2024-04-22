// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fs::File;

use async_trait::async_trait;
use models::NotusResults;
use nasl_interpreter::FSPluginLoader;
use notus::{error::Error, loader::hashsum::HashsumProductLoader, notus::Notus};
use tokio::sync::RwLock;

#[async_trait]
pub trait NotusScanner {
    async fn scan(&self, os: &str, packages: &[String]) -> Result<NotusResults, Error>;
    async fn get_available_os(&self) -> Result<Vec<String>, Error>;
}

#[derive(Debug)]
pub struct NotusWrapper {
    notus: RwLock<Notus<HashsumProductLoader<File, FSPluginLoader<String>>>>,
}

impl NotusWrapper {
    pub fn new(notus: Notus<HashsumProductLoader<File, FSPluginLoader<String>>>) -> Self {
        Self {
            notus: RwLock::new(notus),
        }
    }
}

#[async_trait]
impl NotusScanner for NotusWrapper {
    async fn scan(&self, os: &str, packages: &[String]) -> Result<NotusResults, Error> {
        self.notus.write().await.scan(os, packages)
    }

    async fn get_available_os(&self) -> Result<Vec<String>, Error> {
        self.notus.read().await.get_available_os()
    }
}
