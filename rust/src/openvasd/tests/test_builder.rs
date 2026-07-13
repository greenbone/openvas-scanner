// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::BTreeMap,
    error::Error,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

use anyhow::bail;
use http::StatusCode;
use reqwest::Method;
use serde::{Serialize, de::DeserializeOwned, ser::SerializeMap};
use tokio::time::Instant;

use crate::{build_runtime, config::Config};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SLEEP_INTERVAL: Duration = Duration::from_millis(100);

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

/// This is just a wrapper type to make it convenient to
/// 1. Parse the body of a response in a given format via the
///    serialize impl of a type (S)
/// 2. Call `.snapshot()` on this type to write a snapshot with
///    an appropriate name
pub struct BodySnapshot<S: Serialize + DeserializeOwned> {
    inner: S,
}

impl<S: Serialize + DeserializeOwned> BodySnapshot<S> {
    pub fn snapshot(self, name: &str) {
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_ron_snapshot!(name, self.inner);
        });
    }
}

pub struct Response {
    snapshot: ResponseSnapshot,
    name: String,
}

impl Response {
    async fn from_reqwest(name: &str, value: reqwest::Response) -> Self {
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
            name: name.to_string(),
        }
    }

    pub fn snapshot(&self) -> &Self {
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_ron_snapshot!(self.name.clone(), self.snapshot);
        });
        self
    }

    pub fn custom_snapshot<S>(&self, name: &str, f: impl Fn(&ResponseSnapshot) -> S) -> &Self
    where
        S: Serialize,
    {
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_ron_snapshot!(format!("{}_{}", self.name, name), f(&self.snapshot));
        });
        self
    }

    #[track_caller]
    pub fn assert_status(&self, status_code: StatusCode) -> &Self {
        assert_eq!(status_code, self.snapshot.status_code);
        self
    }

    fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.snapshot.status_code).unwrap()
    }

    pub fn body<S: DeserializeOwned + Serialize>(&self) -> BodySnapshot<S> {
        BodySnapshot {
            inner: serde_json::from_str(&self.snapshot.body).unwrap(),
        }
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

pub struct WaitForStatus {
    /// The status code we want to wait for
    status: StatusCode,
    /// The status code we expect to receive while we are waiting for `status`.
    intermediate_status: Option<StatusCode>,
    /// The timeout after which we will return an error
    timeout: Duration,
    /// The sleep time to wait between subsequent requests.
    interval: Duration,
}

impl From<StatusCode> for WaitForStatus {
    fn from(code: StatusCode) -> Self {
        Self {
            status: code,
            intermediate_status: None,
            timeout: DEFAULT_TIMEOUT,
            interval: DEFAULT_SLEEP_INTERVAL,
        }
    }
}

pub trait WaitForStatusExt {
    fn with_timeout(self, timeout: Duration) -> WaitForStatus;
    fn with_intermediate_status(self, status: StatusCode) -> WaitForStatus;
}

impl<T> WaitForStatusExt for T
where
    T: Into<WaitForStatus>,
{
    fn with_timeout(self, timeout: Duration) -> WaitForStatus {
        let mut wait = self.into();
        wait.timeout = timeout;
        wait
    }

    fn with_intermediate_status(self, status: StatusCode) -> WaitForStatus {
        let mut wait = self.into();
        wait.intermediate_status = Some(status);
        wait
    }
}

pub struct Request<S> {
    method: Method,
    path: &'static str,
    address: SocketAddr,
    test_name: String,
    json: Option<S>,
    /// Controls the behavior of this request. If unset, we simplify perform the
    /// request and return the Response.
    ///
    /// If set, we wait for the request to reach the desired status and then
    /// return the final response (the one that had the correct status code). If
    /// we never reach the correct status, we panic, since we consider this case
    /// a test failure.
    wait_for_status: Option<WaitForStatus>,
}

impl Request<()> {
    // The bounds are not required here but results in type errors earlier than deferring
    // to the `IntoFuture` impl below, so it will hopefully be clearer to the user.
    pub fn json<S: Serialize + Send + Sync + 'static>(self, json: S) -> Request<S> {
        // Have to be explicit about each field here instead of assigning to self.json, since the
        // types are different
        Request {
            method: self.method,
            path: self.path,
            address: self.address,
            test_name: self.test_name,
            json: Some(json),
            wait_for_status: None,
        }
    }
}

impl<S: Serialize> Request<S> {
    pub fn wait_for_status(mut self, wait_for_status: impl Into<WaitForStatus>) -> Self {
        self.wait_for_status = Some(wait_for_status.into());
        self
    }

    fn build_reqwest_request(&self) -> reqwest::RequestBuilder {
        let mut request = reqwest::Client::new().request(
            self.method.clone(),
            format!("http://{}{}", self.address, self.path),
        );
        if let Some(ref json) = self.json {
            request = request.json(json);
        }
        request
    }

    async fn get_response(&self) -> Response {
        let reqwest = self.build_reqwest_request();
        let test_name = format!("{} {} {}", self.test_name, self.method, self.path);
        Response::from_reqwest(&test_name, reqwest.send().await.unwrap()).await
    }

    async fn run(self) -> Response {
        if let Some(ref wait) = self.wait_for_status {
            let started = Instant::now();
            loop {
                let response = self.get_response().await;
                if response.status() == wait.status {
                    return response;
                } else if let Some(ref intermediate_status) = wait.intermediate_status
                    && response.status() != *intermediate_status
                {
                    panic!(
                        "While waiting for {} at {}, to return {}, we found the intermediate status {}, but expected {}",
                        self.method,
                        self.path,
                        wait.status,
                        response.status(),
                        intermediate_status
                    );
                }

                if started.elapsed() >= wait.timeout {
                    panic!(
                        "Reached {}s timeout waiting for {} at {} to return status {}. Found status {} instead.",
                        wait.timeout.as_secs(),
                        self.method,
                        self.path,
                        wait.status,
                        response.status()
                    )
                }

                tokio::time::sleep(wait.interval).await;
            }
        } else {
            self.get_response().await
        }
    }
}

impl<S: Serialize + Send + Sync + 'static> IntoFuture for Request<S> {
    type Output = Response;

    type IntoFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.run().await })
    }
}

impl OpenvasdInstance {
    // The generic is completely unnecessary here, since we never call serialize
    // on a request without json,
    pub fn request(&self, method: Method, path: &'static str) -> Request<()> {
        Request {
            method,
            path,
            test_name: self.test_name.clone(),
            address: self.address,
            json: None,
            wait_for_status: None,
        }
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
    let started = Instant::now();
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
