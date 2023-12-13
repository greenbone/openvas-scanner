// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod config;
use models::{Phase, Result as ScanResult, Status};
use reqwest::header;

use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;

/// Creates a new client setting the header, API-KEY and Certs if existing
pub fn new_client(
    apikey: Option<&String>,
    cert: Option<&String>,
    key: Option<&String>,
) -> reqwest::Client {
    let mut headers = header::HeaderMap::new();
    if let Some(k) = apikey {
        headers.insert("X-API-KEY", header::HeaderValue::from_str(k).unwrap());
    }
    headers.insert(
        "Content-Type",
        header::HeaderValue::from_static("application/json"),
    );
    let cli = reqwest::Client::builder().default_headers(headers);

    // There are key-cert credentials
    if let Some(k) = key {
        if let Some(c) = cert {
            let mut file = File::open(k).unwrap_or_else(|_| panic!("{k} not found"));
            let mut ident = String::new();
            file.read_to_string(&mut ident).unwrap();

            let mut file = File::open(c).unwrap_or_else(|_| panic!("{c} not found"));
            let mut aux = String::new();
            file.read_to_string(&mut aux).unwrap();

            ident.push_str(&aux);
            let identity = reqwest::Identity::from_pem(&ident.into_bytes()).unwrap();
            return cli
                .identity(identity)
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();
        }
    }

    cli.build().unwrap()
}

/// Stores the Scan Config and returns the received ScanID, to be used in further requests.
pub async fn create_scan(
    cli: &reqwest::Client,
    server: &String,
    scan_config: &String,
) -> Option<String> {
    let mut file = File::open(scan_config).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();

    let mut path = String::from(server);
    path.push_str("/scans");
    let res = cli.post(path).body(content).send().await.unwrap();

    if res.status().is_success() {
        tracing::info!("\tCreating scan config OK");
        let id = res.json().await.unwrap();
        return Some(id);
    }

    tracing::info!("\tCreating scan config '{scan_config}' FAILED");
    None
}

/// Sends an action for the given ScanID.
pub async fn scan_action(cli: &reqwest::Client, server: &String, id: &str, action: String) -> bool {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id);

    let mut data = HashMap::new();
    data.insert("action", action.as_str());
    let res = cli.post(path).json(&data).send().await.unwrap();

    if res.status().is_success() {
        tracing::info!("\tSend scan action {action} OK");
        return true;
    }

    tracing::info!("\tSend scan action {action} FAILED");
    false
}

/// Given an ScanID, it fetches the current scan status.
pub async fn scan_status(cli: &reqwest::Client, server: &String, id: &str) -> Option<Phase> {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id);
    path.push_str("/status");

    let res = cli.get(path).send().await.unwrap();

    if res.status().is_success() {
        let data = res.text().await.unwrap();
        if data.is_empty() {
            return None;
        }
        let status: Result<Status, _> = serde_json::from_str(data.as_str());
        match status {
            Ok(st) => {
                return Some(st.status);
            }
            Err(err) => {
                println!("{:?}", err);
                return None;
            }
        }
    }
    tracing::info!("\tGet scan status FAILED");
    None
}

/// Given an ScanID, it fetches the current scan results.
pub async fn scan_results(
    cli: &reqwest::Client,
    server: &String,
    id: &str,
) -> Option<Vec<ScanResult>> {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id);
    path.push_str("/results");

    let res = cli.get(path).send().await.unwrap();

    if res.status().is_success() {
        let data = res.text().await.unwrap();
        if data.is_empty() {
            return None;
        }
        let results: Result<Vec<ScanResult>, _> = serde_json::from_str(data.as_str());
        match results {
            Ok(res) => {
                return Some(res);
            }
            Err(err) => {
                println!("{:?}", err);
                return None;
            }
        }
    }
    tracing::info!("\tGet scan results FAILED");
    None
}

pub async fn delete_scan(cli: &reqwest::Client, server: &String, id: &str) -> bool {
    let mut path = String::from(server);
    path.push_str("/scans/");
    path.push_str(id);

    let res = cli.delete(path).send().await.unwrap();

    if res.status().is_success() {
        tracing::info!("\tDelete scan OK");
        return true;
    }
    tracing::info!("\tDelete scan FAILED");
    false
}
