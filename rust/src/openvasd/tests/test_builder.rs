// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::BTreeMap,
    error::Error,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::bail;
use reqwest::Method;
use serde::{Serialize, ser::SerializeMap};

use crate::{build_runtime, config::Config};

pub struct ResponseSnapshot {
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl Serialize for ResponseSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // This is a little ugly, but we serialize this manually
        // to improve the formatting of the snapshots slightly
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("status_code", &self.status_code)?;
        map.serialize_entry("headers", &self.headers)?;
        map.serialize_entry("body", &self.body)?;
        map.end()
    }
}

pub struct Response {
    snapshot: ResponseSnapshot,
    name: String,
}

impl Response {
    async fn from_reqwest(name: String, value: reqwest::Response) -> Self {
        let headers: BTreeMap<String, String> = value
            .headers()
            .iter()
            .filter(|(k, _)| !header_should_be_redacted(k.as_str()))
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().into()))
            .collect();
        Self {
            snapshot: ResponseSnapshot {
                status_code: value.status().as_u16(),
                headers,
                body: value.text().await.unwrap(),
            },
            name,
        }
    }

    pub fn snapshot(&self) -> &Self {
        insta::assert_ron_snapshot!(self.name.clone(), self.snapshot);
        self
    }

    pub fn custom_snapshot<S>(&self, name: &str, f: impl Fn(&ResponseSnapshot) -> S) -> &Self
    where
        S: Serialize,
    {
        insta::assert_ron_snapshot!(name, f(&self.snapshot));
        self
    }
}

fn header_should_be_redacted(k: &str) -> bool {
    k == "date"
}

pub struct TestBuilder {
    name: String,
    config: Option<PathBuf>,
}

impl TestBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            config: None,
        }
    }

    pub fn config(mut self, name: &str) -> Self {
        self.config = Some(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("data/tests/scanner/config")
                .join(format!("{name}.toml")),
        );
        self
    }

    fn config_path(&self) -> PathBuf {
        self.config.clone().unwrap()
    }

    fn read_config(&self) -> Config {
        Config::from_file(self.config_path())
    }

    async fn build_internal(self) -> anyhow::Result<OpenvasdInstance> {
        let address = unused_local_address().expect("allocate openvasd test listener");

        let mut config = self.read_config();
        config.listener.address = address;
        let runtime = build_runtime(config)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        let mut task = tokio::spawn(async move { runtime.run_blocking().await });
        tokio::select! {
            result = wait_for_listener(address) => result?,
            result = &mut task => {
                match result {
                    Ok(Ok(code)) => bail!("openvasd exited before accepting connections with code {code}"),
                    Ok(Err(error)) => bail!("openvasd failed before accepting connections: {error}"),
                    Err(error) => bail!("openvasd task failed before accepting connections: {error}"),
                }
            }
        }

        Ok(OpenvasdInstance {
            address,
            test_name: self.name,
            task,
        })
    }

    pub async fn build(self) -> OpenvasdInstance {
        self.build_internal().await.unwrap()
    }
}

pub struct OpenvasdInstance {
    pub address: SocketAddr,
    test_name: String,
    task: tokio::task::JoinHandle<Result<i32, Box<dyn Error + Send + Sync>>>,
}

impl OpenvasdInstance {
    pub async fn request(&self, method: Method, path: &str) -> Response {
        Response::from_reqwest(
            format!("{} {} {}", self.test_name, method, path),
            reqwest::Client::new()
                .request(method, format!("http://{}{}", self.address, path))
                .send()
                .await
                .unwrap(),
        )
        .await
    }
}

impl Drop for OpenvasdInstance {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn unused_local_address() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.local_addr()
}

async fn wait_for_listener(address: SocketAddr) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    loop {
        match tokio::net::TcpStream::connect(address).await {
            Ok(_) => return Ok(()),
            Err(error) if started.elapsed() >= Duration::from_secs(5) => {
                bail!("wait for openvasd to accept connections on {address}. {error}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}
