// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::env;

#[derive(Debug)]
pub struct Args {
    /// openvasd
    openvasd: String,
    /// Scan Config
    scan_config: String,
    /// API KEY
    api_key: String,
    /// Client certificate
    cert: String,
    /// Client private key
    key: String,
}

impl Args {
    pub fn openvasd(&self) -> &String {
        &self.openvasd
    }
    pub fn scan_config(&self) -> &String {
        &self.scan_config
    }
    pub fn api_key(&self) -> Option<&String> {
        match self.api_key.is_empty() {
            true => None,
            false => Some(&self.api_key),
        }
    }
    pub fn key(&self) -> Option<&String> {
        match self.key.is_empty() {
            true => None,
            false => Some(&self.key),
        }
    }
    pub fn cert(&self) -> Option<&String> {
        match self.cert.is_empty() {
            true => None,
            false => Some(&self.cert),
        }
    }

    pub fn get_all() -> Self {
        Self {
            openvasd: env::var("OPENVASD_SERVER").unwrap_or_default(),
            scan_config: env::var("SCAN_CONFIG").unwrap_or_default(),
            api_key: env::var("API_KEY").unwrap_or_default(),
            key: env::var("CLIENT_KEY").unwrap_or_default(),
            cert: env::var("CLIENT_CERT").unwrap_or_default(),
        }
    }
}
