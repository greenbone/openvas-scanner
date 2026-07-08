// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    ops::Deref,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::bail;
use http::StatusCode;

use crate::{build_runtime, config::Config};

pub struct Response {
    status_code: StatusCode,
    body: String,
}

impl Response {
    async fn from_reqwest(value: reqwest::Response) -> Self {
        Self {
            status_code: value.status(),
            body: value.text().await.unwrap(),
        }
    }
}

pub struct HealthReady(Response);

pub struct TestBuilder {
    config: Option<PathBuf>,
}

impl TestBuilder {
    pub fn new() -> Self {
        Self { config: None }
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

    pub async fn build(self) -> anyhow::Result<OpenvasdInstance> {
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

        Ok(OpenvasdInstance { address, task })
    }
}

pub struct OpenvasdInstance {
    pub address: SocketAddr,
    task: tokio::task::JoinHandle<Result<i32, Box<dyn Error + Send + Sync>>>,
}

impl OpenvasdInstance {
    pub async fn health_ready(&self) -> HealthReady {
        HealthReady(
            Response::from_reqwest(
                reqwest::get(format!("http://{}/health/ready", self.address))
                    .await
                    .unwrap(),
            )
            .await,
        )
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

impl Deref for HealthReady {
    type Target = Response;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Response {
    pub fn snapshot(&self) -> &Self {
        let status_code = self.status_code;
        let body = &self.body;
        insta::assert_snapshot!(format!("status: {status_code}\nbody: {body}"));
        self
    }
}
