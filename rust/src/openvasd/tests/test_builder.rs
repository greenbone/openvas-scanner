// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::BTreeMap,
    error::Error,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

use anyhow::{Context, bail};
use http::StatusCode;
use reqwest::Method;
use scannerlib::models::{self, Phase};
use serde::{Serialize, de::DeserializeOwned, ser::SerializeMap};
use tokio::time::Instant;

use crate::{build_runtime, config::Config};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SLEEP_INTERVAL: Duration = Duration::from_millis(100);

/// This is just a wrapper type to make it convenient to
/// 1. Parse the body of a response in a given format via the
///    serialize impl of a type (S)
/// 2. Call `.snapshot()` on this type to write a snapshot with
///    an appropriate name
pub struct BodySnapshot<S: Serialize + DeserializeOwned> {
    inner: S,
    name_prefix: String,
}

impl<S: Serialize + DeserializeOwned> BodySnapshot<S> {
    pub fn snapshot(self, name: &str) {
        insta::with_settings!({ prepend_module_to_snapshot => false }, {
            insta::assert_ron_snapshot!(format!("{}_{}", self.name_prefix, name), self.inner);
        });
    }
}

impl<S: Serialize + DeserializeOwned> Deref for BodySnapshot<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Serialize + DeserializeOwned> DerefMut for BodySnapshot<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// This is a wrapper type to represent the relevant
/// and "snapshottable" parts of a `Response`.
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
            name_prefix: self.name.clone(),
        }
    }

    pub fn body_str(&self) -> String {
        serde_json::from_str::<String>(&self.snapshot.body)
            .unwrap()
            .clone()
    }
}

fn header_should_be_redacted(k: &str) -> bool {
    k == "date"
}

pub struct Test {
    name: String,
    config: Option<PathBuf>,
}

impl Test {
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

    async fn build(self) -> OpenvasdInstance {
        self.build_internal().await.unwrap()
    }
}

// This is just convenience to avoid having to call `.build()` explicitly
impl IntoFuture for Test {
    type Output = OpenvasdInstance;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output>>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.build().await })
    }
}

pub struct OpenvasdInstance {
    pub address: SocketAddr,
    test_name: String,
    task: tokio::task::JoinHandle<Result<i32, Box<dyn Error + Send + Sync>>>,
}

pub enum Condition {
    StatusCode(StatusCode),
    ScanPhase(models::Phase),
}

impl Condition {
    fn check(&self, response: &Response) -> anyhow::Result<()> {
        match self {
            Self::StatusCode(code) => {
                if response.status() == *code {
                    Ok(())
                } else {
                    bail!("Expected status {}, found {}.", code, response.status())
                }
            }
            Self::ScanPhase(expected) => {
                let phase = &response.body::<models::Status>().status;
                if phase == expected {
                    Ok(())
                } else {
                    bail!("Expected phase {}, found {}.", expected, phase)
                }
            }
        }
    }
}

pub struct WaitFor {
    /// The condition we want to wait for
    condition: Condition,
    /// The condition we expect to receive while we are waiting for `condition`.
    intermediate_condition: Option<Condition>,
    /// The timeout after which we will return an error
    timeout: Duration,
    /// The sleep time to wait between subsequent requests.
    interval: Duration,
}

impl From<StatusCode> for WaitFor {
    fn from(code: StatusCode) -> Self {
        Self {
            condition: Condition::StatusCode(code),
            intermediate_condition: None,
            timeout: DEFAULT_TIMEOUT,
            interval: DEFAULT_SLEEP_INTERVAL,
        }
    }
}

impl From<Phase> for WaitFor {
    fn from(phase: Phase) -> Self {
        Self {
            condition: Condition::ScanPhase(phase),
            intermediate_condition: None,
            timeout: DEFAULT_TIMEOUT,
            interval: DEFAULT_SLEEP_INTERVAL,
        }
    }
}

pub trait WaitForStatusExt {
    fn with_timeout(self, timeout: Duration) -> WaitFor;
    fn with_intermediate_status(self, status: StatusCode) -> WaitFor;
}

impl<T> WaitForStatusExt for T
where
    T: Into<WaitFor>,
{
    fn with_timeout(self, timeout: Duration) -> WaitFor {
        let mut wait = self.into();
        wait.timeout = timeout;
        wait
    }

    fn with_intermediate_status(self, status: StatusCode) -> WaitFor {
        let mut wait = self.into();
        wait.intermediate_condition = Some(Condition::StatusCode(status));
        wait
    }
}

pub struct Request<S> {
    method: Method,
    path: String,
    address: SocketAddr,
    test_name: String,
    json: Option<S>,
    /// Controls the behavior of this request. If unset, we simplify perform the
    /// request and return the Response.
    ///
    /// If set, we wait for the request to reach the desired condition and then
    /// return the final response (the one that fulfilled the condition). If
    /// we never reach the correct condition before the timeout, we panic.
    wait_for: Option<WaitFor>,
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
            wait_for: None,
        }
    }
}

impl<S: Serialize> Request<S> {
    pub fn wait_for(mut self, wait_for: impl Into<WaitFor>) -> Self {
        self.wait_for = Some(wait_for.into());
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
        if let Some(ref wait) = self.wait_for {
            let started = Instant::now();
            loop {
                let response = self.get_response().await;
                match wait
                    .condition
                    .check(&response)
                    .context(format!("At path {} {}", self.method, self.path))
                {
                    Ok(_) => {
                        return response;
                    }
                    Err(e) => {
                        if started.elapsed() >= wait.timeout {
                            panic!("Reached {}s timeout. {e}", wait.timeout.as_secs());
                        } else if let Some(ref intermediate) = wait.intermediate_condition
                            && let Err(e) = intermediate.check(&response)
                        {
                            panic!(
                                "Wrong intermediate condition at path {} {}: {e}",
                                self.method, self.path
                            );
                        }
                    }
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
    pub fn request(&self, method: Method, path: impl Into<String>) -> Request<()> {
        let path = path.into();
        Request {
            method,
            path,
            test_name: self.test_name.clone(),
            address: self.address,
            json: None,
            wait_for: None,
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
