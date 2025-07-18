// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines the entry point for the controller.
//!
//! All known paths must be handled in the entrypoint function.

use core::str;
use std::{fmt::Display, marker::PhantomData, sync::Arc};

use super::{ClientIdentifier, context::Context};

use http::StatusCode;
use hyper::{Method, Request};
use regex::Regex;
use scannerlib::models::scanner::{ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper};
use scannerlib::models::{Action, Phase, Scan, ScanAction, scanner::*};
use scannerlib::notus::NotusError;
use scannerlib::scanner::preferences::preference;
use tokio::process::Command;

use crate::storage::{self, MappedID};
use crate::{
    config,
    controller::ClientHash,
    notus::NotusScanner,
    scheduling,
    storage::{NVTStorer as _, ProgressGetter as _, ScanIDClientMapper as _, ScanStorer as _},
};

const PERFORMANCE_TITLES: &str = r"(cpu-.*)|(proc)|(mem)|(swap)|(load)|(df-.*)|(disk-sd[a-z][0-9]-rw)|(disk-sd[a-z][0-9]-load)|(disk-sd[a-z][0-9]-io-load)|(interface-eth.*-traffic)|(interface-eth.*-err-rate)|(interface-eth.*-err)|(sensors-.*_temperature-.*)|(sensors-.*_fanspeed-.*)|(sensors-.*_voltage-.*)|(titles)";
const PERFORMANCE_TITLES_FORBIDDEN: &str = r"^[^|&;]+$";

#[derive(PartialEq, Eq)]
enum HealthOpts {
    /// Ready
    Ready,
    /// Started
    Started,
    /// Alive
    Alive,
    /// Performance
    Performance,
}
/// The supported paths of openvasd
// TODO: change KnownPath to reflect query parameter
#[derive(PartialEq, Eq)]
enum KnownPaths {
    /// /scans/{id}
    Scans(Option<String>),
    /// /scans/preferences
    ScanPreferences,
    /// /scans/{id}/results/{result_id}
    ScanResults(String, Option<String>),
    /// /scans/{id}/status
    ScanStatus(String),
    /// /vts
    Vts(Option<String>),
    /// /health
    Health(HealthOpts),
    /// /notus/{os}
    Notus(Option<String>),
    /// Not supported
    Unknown,
}

impl KnownPaths {
    pub fn requires_id(&self) -> bool {
        !matches!(
            self,
            Self::Unknown | Self::Health(_) | Self::Vts(_) | Self::Notus(_)
        )
    }

    #[tracing::instrument]
    /// Parses a path and returns the corresponding `KnownPaths` variant.
    fn from_path(path: &str, mode: &config::Mode) -> Self {
        let mut parts = path.split('/').filter(|s| !s.is_empty());
        match parts.next() {
            Some("scans") => match mode {
                config::Mode::Service => {
                    tracing::debug!(?mode, ?path);
                    match parts.next() {
                        Some(id) => match parts.next() {
                            Some("results") => KnownPaths::ScanResults(
                                id.to_string(),
                                parts.next().map(|s| s.to_string()),
                            ),
                            Some("status") => KnownPaths::ScanStatus(id.to_string()),
                            Some(_) => KnownPaths::Unknown,
                            None => {
                                if id == "preferences" {
                                    KnownPaths::ScanPreferences
                                } else {
                                    KnownPaths::Scans(Some(id.to_string()))
                                }
                            }
                        },
                        None => KnownPaths::Scans(None),
                    }
                }
                config::Mode::ServiceNotus => {
                    tracing::debug!(?mode, ?path, "Scan endpoint disabled");
                    KnownPaths::Unknown
                }
            },
            Some("vts") => match parts.next() {
                Some(oid) => KnownPaths::Vts(Some(oid.to_string())),
                None => KnownPaths::Vts(None),
            },
            Some("notus") => match parts.next() {
                Some(os) => KnownPaths::Notus(Some(os.to_string())),
                None => KnownPaths::Notus(None),
            },
            Some("health") => match parts.next() {
                Some("ready") => KnownPaths::Health(HealthOpts::Ready),
                Some("alive") => KnownPaths::Health(HealthOpts::Alive),
                Some("started") => KnownPaths::Health(HealthOpts::Started),
                Some("performance") => KnownPaths::Health(HealthOpts::Performance),
                _ => KnownPaths::Unknown,
            },
            _ => {
                tracing::trace!(?path, "Unknown");
                KnownPaths::Unknown
            }
        }
    }

    fn scan_id(&self) -> Option<&str> {
        match self {
            Self::Scans(Some(id)) | Self::ScanResults(id, _) | Self::ScanStatus(id) => Some(id),
            _ => None,
        }
    }
}

impl Display for KnownPaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnownPaths::Scans(Some(id)) => write!(f, "/scans/{id}"),
            KnownPaths::Scans(None) => write!(f, "/scans"),
            KnownPaths::ScanResults(id, Some(result_id)) => {
                write!(f, "/scans/{id}/results/{result_id}")
            }
            KnownPaths::ScanResults(id, None) => write!(f, "/scans/{id}/results"),
            KnownPaths::ScanStatus(id) => write!(f, "/scans/{id}/status"),
            KnownPaths::Unknown => write!(f, "Unknown"),
            KnownPaths::Vts(None) => write!(f, "/vts"),
            KnownPaths::Vts(Some(oid)) => write!(f, "/vts/{oid}"),
            KnownPaths::Notus(Some(os)) => write!(f, "/notus/{os}"),
            KnownPaths::Notus(None) => write!(f, "/notus"),
            KnownPaths::Health(HealthOpts::Alive) => write!(f, "/health/alive"),
            KnownPaths::Health(HealthOpts::Ready) => write!(f, "/health/ready"),
            KnownPaths::Health(HealthOpts::Started) => write!(f, "/health/started"),
            KnownPaths::Health(HealthOpts::Performance) => write!(f, "/health/performance"),
            KnownPaths::ScanPreferences => write!(f, "/scans/preferences"),
        }
    }
}

pub struct EntryPoint<S, DB, R> {
    pub ctx: Arc<Context<S, DB>>,
    pub cid: Arc<ClientIdentifier>,
    _phantom: PhantomData<R>,
}

impl<S, DB, R> EntryPoint<S, DB, R> {
    pub fn new(ctx: Arc<Context<S, DB>>, cid: Arc<ClientIdentifier>) -> EntryPoint<S, DB, R> {
        Self {
            ctx,
            cid,
            _phantom: PhantomData,
        }
    }
}

impl<S, DB, R> hyper::service::Service<Request<R>> for EntryPoint<S, DB, R>
where
    S: ScanStarter
        + ScanStopper
        + ScanDeleter
        + ScanResultFetcher
        + std::marker::Send
        + std::marker::Sync
        + 'static,
    DB: crate::storage::Storage + std::marker::Send + 'static + std::marker::Sync,
    R: hyper::body::Body + Send + 'static,
    <R as hyper::body::Body>::Error: std::error::Error,
    <R as hyper::body::Body>::Data: Send,
{
    type Response = crate::response::Result;

    type Error = Error;

    type Future = std::pin::Pin<
        Box<dyn futures_util::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: Request<R>) -> Self::Future {
        let ctx = self.ctx.clone();
        let cid = self.cid.clone();
        Box::pin(async move {
            use KnownPaths::*;
            let kp = KnownPaths::from_path(req.uri().path(), &ctx.mode);
            // on head requests we just return an empty response, except for /scans
            if req.method() == Method::HEAD && kp != KnownPaths::Scans(None) {
                return Ok(ctx.response.empty(StatusCode::OK));
            }
            if kp == KnownPaths::Health(HealthOpts::Performance) && !&ctx.enable_get_performance {
                return Ok(ctx
                    .response
                    .not_found("entrypoint disable:", req.uri().path()));
            }
            let cid: Option<ClientHash> = {
                match &*cid {
                    ClientIdentifier::Disabled => match ctx.api_key.as_ref() {
                        Some(key) => match req.headers().get("x-api-key") {
                            Some(v) if v == key => ctx.api_key.as_ref().map(|x| x.into()),
                            Some(v) => {
                                tracing::debug!("{} {} invalid key: {:?}", req.method(), kp, v);
                                None
                            }
                            None => None,
                        },
                        _ => Some("disabled".into()),
                    },
                    ClientIdentifier::Known(cid) => Some(cid.clone()),
                    ClientIdentifier::Unknown => {
                        match ctx.api_key.as_ref() {
                            Some(key) => match req.headers().get("x-api-key") {
                                Some(v) if v == key => ctx.api_key.as_ref().map(|x| x.into()),
                                Some(v) => {
                                    tracing::debug!("{} {} invalid key: {:?}", req.method(), kp, v);
                                    None
                                }
                                None => None,
                            },
                            _ => {
                                // We don't allow no api key and no client certs when we have a server
                                // certificate to prevent accidental misconfiguration.
                                None
                            }
                        }
                    }
                }
            };

            if kp.requires_id() && cid.is_none() {
                tracing::debug!("{} {} unauthorized", req.method(), kp);
                return Ok(ctx.response.unauthorized());
            }
            let cid = cid.unwrap_or_default();
            //TODO: although it is ugly, when moving to greenbone-scanner-framework this test will
            //be handled differently. Therefore I leave it as is, although it is misleading.
            let mapped_id = match kp.scan_id() {
                Some(id) => match ctx.scheduler.get_mapped_id(&cid, id).await {
                    Ok(x) => x,
                    Err(storage::Error::NotFound) => {
                        tracing::debug!(
                            scan_id=id,
                            client=%cid,
                            "Not allowed.",
                        );
                        // we return 404 instead of 401 to not leak any ids
                        return Ok(ctx.response.not_found("scans", id));
                    }
                    Err(error) => {
                        return Ok(ctx.response.internal_server_error(&error));
                    }
                },
                None => MappedID::default(),
            };

            tracing::debug!(
                method=%req.method(),
                path=req.uri().path(),
                query=req.uri().query(),
                "process call",
            );
            match (req.method(), kp) {
                (&Method::HEAD, Scans(None)) => Ok(ctx.response.empty(StatusCode::NO_CONTENT)),
                (&Method::GET, Health(HealthOpts::Alive))
                | (&Method::GET, Health(HealthOpts::Started)) => {
                    Ok(ctx.response.empty(StatusCode::OK))
                }
                (&Method::GET, Health(HealthOpts::Ready)) => {
                    let oids = ctx.scheduler.oids().await?;
                    if oids.is_empty() {
                        Ok(ctx.response.empty(StatusCode::SERVICE_UNAVAILABLE))
                    } else {
                        Ok(ctx.response.empty(StatusCode::OK))
                    }
                }
                (&Method::GET, Health(HealthOpts::Performance)) => {
                    let query = req.uri().query();
                    if query.is_none() {
                        return Ok(ctx.response.bad_request("Bogus GET performance format"));
                    }

                    let mut child = Command::new("gvmcg");
                    let query_parts = query.unwrap().split("&");
                    let mut t = "";
                    let mut start = "";
                    let mut end = "";

                    let re_titles = Regex::new(PERFORMANCE_TITLES).unwrap();
                    let re_forbidden = Regex::new(PERFORMANCE_TITLES_FORBIDDEN).unwrap();
                    for p in query_parts {
                        let keyval = p.split("=").collect::<Vec<&str>>();
                        if keyval.len() < 2 {
                            return Ok(ctx.response.bad_request("Bogus GET performance format"));
                        }
                        match keyval[0] {
                            "start" => {
                                start = match keyval[1].parse::<i64>() {
                                    Ok(_) => keyval[1],
                                    Err(_) => {
                                        return Ok(ctx.response.bad_request(
                                            "Bogus GET performance format. Invalid start value",
                                        ));
                                    }
                                };
                            }
                            "end" => {
                                end = match keyval[1].parse::<i64>() {
                                    Ok(_) => keyval[1],
                                    Err(_) => {
                                        return Ok(ctx.response.bad_request(
                                            "Bogus GET performance format. Invalid end value",
                                        ));
                                    }
                                };
                            }
                            "titles" => {
                                if re_titles.is_match(keyval[1]) && re_forbidden.is_match(keyval[1])
                                {
                                    t = keyval[1];
                                } else {
                                    return Ok(ctx.response.bad_request(
                                        "Bogus GET performance format. Argument not allowed",
                                    ));
                                };
                            }
                            _ => {
                                return Ok(ctx
                                    .response
                                    .bad_request("Bogus GET performance format"));
                            }
                        };
                    }
                    if !start.is_empty() {
                        child.arg(start);
                    }
                    if !end.is_empty() {
                        child.arg(end);
                    }

                    let child = child.arg(t).output();
                    match child.await {
                        Ok(output) if output.status.success() => {
                            let text_base64 =
                                vec![String::from_utf8_lossy(&output.stdout).replace('\n', "")];
                            Ok(ctx.response.ok(&text_base64))
                        }
                        Ok(output) => Ok(ctx
                            .response
                            .bad_request(str::from_utf8(&output.stderr).unwrap())),
                        Err(output) => Ok(ctx.response.internal_server_error(&output)),
                    }
                }
                (&Method::GET, Notus(None)) => match &ctx.notus {
                    Some(notus) => match notus.get_available_os().await {
                        Ok(result) => Ok(ctx.response.ok(&result)),
                        Err(err) => Ok(ctx.response.internal_server_error(&err)),
                    },
                    None => Ok(ctx.response.empty(StatusCode::SERVICE_UNAVAILABLE)),
                },

                (&Method::POST, Notus(Some(os))) => {
                    match crate::request::json_request::<Vec<String>, _>(&ctx.response, req).await {
                        Ok(packages) => match &ctx.notus {
                            Some(notus) => match notus.scan(&os, &packages).await {
                                Ok(results) => Ok(ctx.response.ok(&results)),
                                Err(err) => match err {
                                    NotusError::UnknownProduct(_) => {
                                        Ok(ctx.response.not_found("advisories", &os))
                                    }
                                    NotusError::PackageParseError(_) => {
                                        Ok(ctx.response.bad_request(&format!("{err}")))
                                    }
                                    _ => Ok(ctx.response.internal_server_error(&err)),
                                },
                            },
                            None => Ok(ctx.response.empty(StatusCode::SERVICE_UNAVAILABLE)),
                        },
                        Err(resp) => Ok(resp),
                    }
                }
                (&Method::POST, Scans(None)) => {
                    match crate::request::json_request::<Scan, _>(&ctx.response, req).await {
                        Ok(mut scan) => {
                            let id = if !scan.scan_id.is_empty() {
                                scan.scan_id.to_string()
                            } else {
                                uuid::Uuid::new_v4().to_string()
                            };

                            if ctx
                                .scheduler
                                .get_scan_ids()
                                .await?
                                .into_iter()
                                .any(|i| *i == id)
                            {
                                tracing::debug!(%id, "Scan ID already in use");
                                return Ok(ctx.response.forbidden_with_reason(
                                    &id,
                                    "Scan ID already in use".to_string(),
                                ));
                            };

                            let resp = ctx.response.created(&id);
                            scan.scan_id.clone_from(&id);

                            if let Some(scan_prefs) = &ctx.scan_preferences {
                                scan_prefs.set_scan_with_preferences(&mut scan);
                            }

                            ctx.scheduler.insert_scan(scan).await?;
                            let mapped_id =
                                ctx.scheduler.generate_mapped_id(cid, id.clone()).await?;
                            tracing::debug!(%id, ?mapped_id, "Scan created");
                            Ok(resp)
                        }
                        Err(resp) => Ok(resp),
                    }
                }
                (&Method::POST, Scans(Some(id))) => {
                    match crate::request::json_request::<ScanAction, _>(&ctx.response, req)
                        .await
                        .map(|a| a.action)
                    {
                        Ok(Action::Start) => {
                            match ctx.scheduler.start_scan_by_id(&id).await {
                                Ok(_) => Ok(ctx.response.no_content()),
                                Err(scheduling::Error::ScanRunning)
                                | Err(scheduling::Error::ScanAlreadyQueued) => {
                                    use Phase::*;
                                    let expected = &[Stored, Stopped, Failed, Succeeded];
                                    Ok(ctx.response.not_accepted(&Requested, expected))
                                }
                                Err(scheduling::Error::NotFound) => {
                                    Ok(ctx.response.not_found("scan", &id))
                                }
                                Err(scheduling::Error::QueueFull) => {
                                    Ok(ctx.response.service_unavailable(
                                        "Queue is already full. Try again later.",
                                    ))
                                }
                                Err(scheduling::Error::UnsupportedResume) => {
                                    Ok(ctx.response.not_implemented("Resuming task is currently not possible, please create a new scan excluding the finished hosts."))
                                }
                                Err(e) => Ok(ctx.response.internal_server_error(&e)),
                            }
                        }
                        Ok(Action::Stop) => match ctx.scheduler.stop_scan(id).await {
                            Ok(_) => Ok(ctx.response.no_content()),
                            Err(e) => Ok(ctx.response.internal_server_error(&e)),
                        },
                        Err(resp) => Ok(resp),
                    }
                }
                (&Method::GET, Scans(None)) => {
                    if ctx.enable_get_scans {
                        match ctx.scheduler.list_mapped_scan_ids(&cid).await {
                            Ok(scans) => Ok(ctx.response.ok(&scans)),
                            Err(e) => Ok(ctx.response.internal_server_error(&e)),
                        }
                    } else {
                        Ok(ctx.response.not_found("scans", "all"))
                    }
                }
                (&Method::GET, ScanPreferences) => {
                    if let Some(p) = &ctx.scan_preferences {
                        Ok(ctx
                            .response
                            .ok_static(&serde_json::to_string(&p).unwrap().into_bytes()))
                    } else {
                        Ok(ctx
                            .response
                            .ok_static(preference::PREFERENCES_JSON.as_bytes()))
                    }
                }
                (&Method::GET, Scans(Some(_))) => match ctx.scheduler.get_scan(&mapped_id).await {
                    Ok((mut scan, _)) => {
                        let credentials = scan
                            .target
                            .credentials
                            .into_iter()
                            .map(move |c| {
                                let c = c.map_password::<_, Error>(|_| Ok("***".to_string()));
                                c.unwrap()
                            })
                            .collect::<Vec<_>>();
                        scan.target.credentials = credentials;
                        Ok(ctx.response.ok(&scan))
                    }
                    Err(crate::storage::Error::NotFound) => {
                        Ok(ctx.response.not_found("scans", &mapped_id))
                    }
                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                },
                (&Method::GET, ScanStatus(_)) => match ctx.scheduler.get_scan(&mapped_id).await {
                    Ok((_, status)) => Ok(ctx.response.ok(&status)),
                    Err(crate::storage::Error::NotFound) => {
                        Ok(ctx.response.not_found("scans/status", &mapped_id))
                    }
                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                },
                (&Method::DELETE, Scans(Some(_))) => {
                    match ctx.scheduler.delete_scan_by_id(&mapped_id).await {
                        Ok(_) => Ok(ctx.response.no_content()),
                        Err(crate::scheduling::Error::NotFound) => {
                            Ok(ctx.response.not_found("scans", &mapped_id))
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                (&Method::GET, ScanResults(_, index)) => {
                    let (begin, end) = {
                        if let Some(id) = index {
                            match id.parse::<usize>() {
                                Ok(id) => (Some(id), Some(id + 1)),
                                Err(_) => (None, None),
                            }
                        } else {
                            let query = req.uri().query().unwrap_or_default();
                            let mut parts = query.split('=');
                            if parts.next() == Some("range") {
                                let mut range = parts.next().unwrap_or_default().split('-');
                                let begin = range.next().unwrap_or_default().parse::<usize>();
                                let end = range.next().unwrap_or_default().parse::<usize>();
                                match (begin, end) {
                                    (Ok(begin), Ok(end)) => (Some(begin), Some(end + 1)),
                                    (Ok(begin), Err(_)) => (Some(begin), None),
                                    _ => (None, None),
                                }
                            } else {
                                (None, None)
                            }
                        }
                    };

                    match ctx.scheduler.get_results(&mapped_id, begin, end).await {
                        Ok(results) => Ok(ctx.response.byte_stream(StatusCode::OK, results).await),
                        Err(crate::storage::Error::NotFound) => {
                            Ok(ctx.response.not_found("scans/results", &mapped_id))
                        }
                        Err(e) => Ok(ctx.response.internal_server_error(&e)),
                    }
                }

                (&Method::GET, Vts(oid)) => {
                    let query = req.uri().query();

                    let meta = match query {
                        Some("information=true") => true,
                        Some("information=1") => true,
                        Some(_) | None => false,
                    };
                    match oid {
                        Some(oid) => match ctx.scheduler.vt_by_oid(&oid).await? {
                            Some(nvt) => Ok(ctx.response.ok(&nvt)),
                            None => Ok(ctx.response.not_found("nvt", &oid)),
                        },
                        None if meta => Ok(ctx.response.ok(&ctx.scheduler.vts().await?)),
                        None => Ok(ctx.response.ok(&ctx.scheduler.oids().await?)),
                    }
                }
                _ => Ok(ctx.response.not_found("path", req.uri().path())),
            }
        })
    }
}

#[cfg(test)]
pub mod client {
    use std::sync::Arc;

    use async_trait::async_trait;
    use http::StatusCode;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::{
        HeaderMap, Method, Request, body::Bytes, header::HeaderValue, service::HttpService,
    };
    use scannerlib::models::scanner::{
        self, Error, ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper, Scanner,
    };
    use scannerlib::models::{self, Action, Scan, ScanAction, Status};
    use scannerlib::nasl::FSPluginLoader;
    use scannerlib::storage::infisto::{
        CachedIndexFileStorer, ChaCha20IndexFileStorer, IndexedFileStorer,
    };
    use serde::Deserialize;

    use crate::storage::inmemory;
    use crate::storage::results::ResultCatcher;
    use crate::{
        controller::{ClientIdentifier, Context},
        storage::{NVTStorer, file::Storage},
    };

    use super::KnownPaths;

    type StartScan = Arc<Box<dyn Fn(Scan) -> Result<(), Error> + Send + Sync + 'static>>;
    type CanStartScan = Arc<Box<dyn Fn(&Scan) -> bool + Send + Sync + 'static>>;
    type StopScan = Arc<Box<dyn Fn(&str) -> Result<(), Error> + Send + Sync + 'static>>;
    type DeleteScan = Arc<Box<dyn Fn(&str) -> Result<(), Error> + Send + Sync + 'static>>;
    type FetchResults =
        Arc<Box<dyn Fn(&str) -> Result<ScanResults, Error> + Send + Sync + 'static>>;

    /// A fake implementation of the ScannerStack trait.
    ///
    /// This is useful for testing the Scanner implementation.
    pub struct LambdaScannerBuilder {
        start_scan: StartScan,
        can_start_scan: CanStartScan,
        stop_scan: StopScan,
        delete_scan: DeleteScan,
        fetch_results: FetchResults,
    }

    impl Default for LambdaScannerBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LambdaScannerBuilder {
        pub fn new() -> Self {
            Self {
                start_scan: Arc::new(Box::new(|_| Ok(()))),
                can_start_scan: Arc::new(Box::new(|_| true)),
                stop_scan: Arc::new(Box::new(|_| Ok(()))),
                delete_scan: Arc::new(Box::new(|_| Ok(()))),
                fetch_results: Arc::new(Box::new(|_| Ok(ScanResults::default()))),
            }
        }

        pub fn with_start_scan<F>(mut self, f: F) -> Self
        where
            F: Fn(Scan) -> Result<(), Error> + Send + Sync + 'static,
        {
            self.start_scan = Arc::new(Box::new(f));
            self
        }

        pub fn with_can_start_scan<F>(mut self, f: F) -> Self
        where
            F: Fn(&Scan) -> bool + Send + Sync + 'static,
        {
            self.can_start_scan = Arc::new(Box::new(f));
            self
        }

        pub fn with_stop_scan<F>(mut self, f: F) -> Self
        where
            F: Fn(&str) -> Result<(), Error> + Send + Sync + 'static,
        {
            self.stop_scan = Arc::new(Box::new(f));
            self
        }

        pub fn with_delete_scan<F>(mut self, f: F) -> Self
        where
            F: Fn(&str) -> Result<(), Error> + Send + Sync + 'static,
        {
            self.delete_scan = Arc::new(Box::new(f));
            self
        }

        pub fn with_fetch_results<F>(mut self, f: F) -> Self
        where
            F: Fn(&str) -> Result<super::ScanResults, Error> + Send + Sync + 'static,
        {
            self.fetch_results = Arc::new(Box::new(f));
            self
        }

        pub fn build(self) -> LambdaScanner {
            LambdaScanner {
                start_scan: self.start_scan,
                can_start_scan: self.can_start_scan,
                stop_scan: self.stop_scan,
                delete_scan: self.delete_scan,
                fetch_results: self.fetch_results,
            }
        }
    }

    pub struct LambdaScanner {
        start_scan: StartScan,
        can_start_scan: CanStartScan,
        stop_scan: StopScan,
        delete_scan: DeleteScan,
        fetch_results: FetchResults,
    }

    #[async_trait]
    impl ScanStarter for LambdaScanner {
        async fn start_scan(&self, scan: Scan) -> Result<(), Error> {
            let start_scan = self.start_scan.clone();
            tokio::task::spawn_blocking(move || (start_scan)(scan))
                .await
                .unwrap()
        }

        async fn can_start_scan(&self, scan: &Scan) -> bool {
            let can_start_scan = self.can_start_scan.clone();
            let scan = scan.clone();
            tokio::task::spawn_blocking(move || (can_start_scan)(&scan))
                .await
                .unwrap()
        }
    }

    #[async_trait]
    impl ScanStopper for LambdaScanner {
        async fn stop_scan<I>(&self, id: I) -> Result<(), Error>
        where
            I: AsRef<str> + Send + 'static,
        {
            let stop_scan = self.stop_scan.clone();
            let id = id.as_ref().to_string();
            tokio::task::spawn_blocking(move || (stop_scan)(&id))
                .await
                .unwrap()
        }
    }

    #[async_trait]
    impl ScanDeleter for LambdaScanner {
        async fn delete_scan<I>(&self, id: I) -> Result<(), Error>
        where
            I: AsRef<str> + Send + 'static,
        {
            let delete_scan = self.delete_scan.clone();
            let id = id.as_ref().to_string();
            tokio::task::spawn_blocking(move || (delete_scan)(&id))
                .await
                .unwrap()
        }
    }

    #[async_trait]
    impl ScanResultFetcher for LambdaScanner {
        async fn fetch_results<I>(&self, id: I) -> Result<super::ScanResults, Error>
        where
            I: AsRef<str> + Send + 'static,
        {
            let fetch_results = self.fetch_results.clone();
            let id = id.as_ref().to_string();
            tokio::task::spawn_blocking(move || (fetch_results)(&id))
                .await
                .unwrap()
        }
    }

    type HttpResult = Result<crate::response::Result, scanner::Error>;
    type TypeResult<T> = Result<T, scanner::Error>;

    pub struct Client<S, DB> {
        ctx: Arc<Context<S, DB>>,
        cid: Arc<ClientIdentifier>,
    }

    pub async fn in_memory_example_feed() -> Client<
        scannerlib::scanner::Scanner<(
            Arc<ResultCatcher<crate::storage::inmemory::Storage<crate::crypt::ChaCha20Crypt>>>,
            FSPluginLoader,
        )>,
        Arc<ResultCatcher<inmemory::Storage<crate::crypt::ChaCha20Crypt>>>,
    > {
        use crate::file::tests::{example_feeds, nasl_root};
        let storage = crate::storage::inmemory::Storage::default();

        let storage = Arc::new(ResultCatcher::new(storage));

        storage
            .synchronize_feeds(example_feeds().await)
            .await
            .unwrap();
        let nasl_feed_path = nasl_root().await;
        let scanner = scannerlib::scanner::Scanner::with_storage(storage.clone(), &nasl_feed_path);
        Client::authenticated(scanner, storage)
    }
    pub async fn encrypted_file_based_example_feed(
        prefix: &str,
    ) -> Client<
        scannerlib::scanner::Scanner<(
            Arc<ResultCatcher<Storage<ChaCha20IndexFileStorer<IndexedFileStorer>>>>,
            FSPluginLoader,
        )>,
        Arc<ResultCatcher<Storage<ChaCha20IndexFileStorer<IndexedFileStorer>>>>,
    > {
        use crate::file::tests::{example_feeds, nasl_root};
        let storage_dir = format!("/tmp/openvasd/{prefix}_{}", uuid::Uuid::new_v4());

        let key = "testdontbother";
        let feeds = example_feeds().await;
        let storage = crate::storage::file::encrypted(&storage_dir, key, feeds).unwrap();

        let storage = Arc::new(ResultCatcher::new(storage));

        storage
            .synchronize_feeds(example_feeds().await)
            .await
            .unwrap();
        let nasl_feed_path = nasl_root().await;
        let scanner = scannerlib::scanner::Scanner::with_storage(storage.clone(), &nasl_feed_path);
        Client::authenticated(scanner, storage)
    }

    pub async fn fails_to_fetch_results()
    -> Client<LambdaScanner, Arc<ResultCatcher<inmemory::Storage<crate::crypt::ChaCha20Crypt>>>>
    {
        use crate::file::tests::example_feeds;
        let storage = crate::storage::inmemory::Storage::default();
        let storage = Arc::new(ResultCatcher::new(storage));
        storage
            .synchronize_feeds(example_feeds().await)
            .await
            .unwrap();

        let scanner = LambdaScannerBuilder::new()
            .with_fetch_results(|_| Err(scanner::Error::Unexpected("no results".to_string())))
            .build();
        Client::authenticated(scanner, storage)
    }

    pub async fn file_based_example_feed(
        prefix: &str,
    ) -> Client<
        scannerlib::scanner::Scanner<(
            Arc<ResultCatcher<Storage<CachedIndexFileStorer>>>,
            FSPluginLoader,
        )>,
        Arc<ResultCatcher<Storage<CachedIndexFileStorer>>>,
    > {
        use crate::file::tests::{example_feed_file_storage, nasl_root};
        let storage_dir = format!("/tmp/openvasd/{prefix}_{}", uuid::Uuid::new_v4());
        let store = example_feed_file_storage(&storage_dir).await;
        let store = Arc::new(ResultCatcher::new(store));
        let nasl_feed_path = nasl_root().await;
        let scanner = scannerlib::scanner::Scanner::with_storage(store.clone(), &nasl_feed_path);
        Client::authenticated(scanner, store)
    }

    impl<S, DB> Client<S, DB>
    where
        S: Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        pub fn authenticated(scanner: S, db: DB) -> Self {
            let ns = crate::config::Scheduler {
                check_interval: std::time::Duration::from_nanos(10),
                ..Default::default()
            };

            let ctx = Arc::new(
                crate::controller::ContextBuilder::new()
                    .api_key(Some("mtls_is_preferred".to_string()))
                    .scheduler_config(ns)
                    .scanner(scanner)
                    .storage(db)
                    .enable_get_scans(true)
                    .build(),
            );
            let cid = Arc::new(ClientIdentifier::Known("42".into()));
            Self { ctx, cid }
        }

        pub fn set_client(&mut self, cid: ClientIdentifier) {
            self.cid = Arc::new(cid);
        }

        async fn entrypoint<R>(&self, req: Request<R>) -> HttpResult
        where
            R: hyper::body::Body + Send + 'static,
            <R as hyper::body::Body>::Error: std::error::Error,
            <R as hyper::body::Body>::Data: Send,
        {
            let mut entry =
                crate::controller::entry::EntryPoint::new(self.ctx.clone(), self.cid.clone());
            entry.call(req).await
        }

        async fn request_empty(&self, method: Method, url: KnownPaths) -> HttpResult {
            self.request_body(method, url, Empty::<Bytes>::new()).await
        }

        async fn request_json<T>(&self, method: Method, url: KnownPaths, data: &T) -> HttpResult
        where
            T: serde::Serialize + std::fmt::Debug,
        {
            let data = serde_json::to_vec(data).map_err(|x| {
                scanner::Error::Unexpected(format!("Unable to transform {data:?}: {x}"))
            })?;
            let body: Full<Bytes> = Full::from(data);
            self.request_body(method, url, body).await
        }

        async fn request_body<B>(
            &self,
            method: Method,
            url: KnownPaths,
            body: B,
        ) -> Result<crate::response::Result, scanner::Error>
        where
            B: Sync + Send + http_body::Body + 'static,
            <B as http_body::Body>::Data: Send,
            <B as http_body::Body>::Error: std::error::Error,
        {
            let req = Request::builder()
                .uri(url.to_string())
                .method(method)
                .body(body)
                .map_err(|x| {
                    scanner::Error::Unexpected(format!("Unable to create request: {x}"))
                })?;
            self.entrypoint(req).await
        }

        pub async fn scan_status(&self, id: &str) -> TypeResult<Status> {
            let result = self
                .request_empty(Method::GET, KnownPaths::ScanStatus(id.to_string()))
                .await;
            self.parsed(result, StatusCode::OK).await
        }

        pub async fn header(&self) -> TypeResult<HeaderMap<HeaderValue>> {
            let result = self
                .request_empty(Method::HEAD, KnownPaths::Vts(None))
                .await?;
            Ok(result.headers().clone())
        }

        pub async fn scan(&self, id: &str) -> TypeResult<Scan> {
            let result = self
                .request_empty(Method::GET, KnownPaths::Scans(Some(id.to_string())))
                .await;
            self.parsed(result, StatusCode::OK).await
        }

        pub async fn scan_results(
            &self,
            id: &str,
            status: StatusCode,
        ) -> TypeResult<Vec<models::Result>> {
            let result = self
                .request_empty(Method::GET, KnownPaths::ScanResults(id.to_string(), None))
                .await;
            self.parsed(result, status).await
        }
        pub async fn scan_delete(&self, id: &str) -> TypeResult<()> {
            let result = self
                .request_empty(Method::DELETE, KnownPaths::Scans(Some(id.to_string())))
                .await;
            self.no_content(result).await
        }

        pub async fn scan_action(&self, id: &str, action: Action) -> TypeResult<()> {
            let action: ScanAction = action.into();
            let result = self
                .request_json(
                    Method::POST,
                    KnownPaths::Scans(Some(id.to_string())),
                    &action,
                )
                .await;
            self.no_content(result).await
        }

        pub async fn no_content(&self, result: HttpResult) -> TypeResult<()> {
            let resp = result?;
            if resp.status() != 204 {
                return Err(scanner::Error::Unexpected(format!(
                    "Expected 204 for a no-content response but got {}",
                    resp.status()
                )));
            }
            Ok(())
        }

        pub async fn scans(&self) -> TypeResult<Vec<Scan>> {
            let result = self
                .request_empty(Method::GET, KnownPaths::Scans(None))
                .await;
            self.parsed(result, StatusCode::OK).await
        }

        // TODO: deal with that static stuff that prevents deserializiation based on Bytes
        pub async fn scans_preferences(&self) -> TypeResult<String> {
            let result = self
                .request_empty(Method::GET, KnownPaths::ScanPreferences)
                .await;
            let resp = result?;
            if resp.status() != 200 && resp.status() != 201 {
                return Err(scanner::Error::Unexpected(format!(
                    "Expected 200 for a body response but got {}",
                    resp.status()
                )));
            }

            // infallible
            let resp = resp.into_body().collect().await.unwrap().to_bytes();
            String::from_utf8(resp.to_vec())
                .map_err(|x| scanner::Error::Unexpected(format!("lol: {x}")))
        }

        pub async fn scan_create(&self, scan: &Scan) -> TypeResult<String> {
            let result = self
                .request_json(Method::POST, KnownPaths::Scans(None), scan)
                .await;
            self.parsed(result, StatusCode::CREATED).await
        }

        pub async fn vts(&self) -> TypeResult<Vec<String>> {
            let result = self.request_empty(Method::GET, KnownPaths::Vts(None)).await;
            self.parsed(result, StatusCode::OK).await
        }

        /// Starts a scan and wait until is finished and returns it status and results
        ///
        pub async fn scan_finish(&self, scan: &Scan) -> TypeResult<(String, Status)> {
            let id = self.scan_create(scan).await?;
            self.scan_action(&id, Action::Start).await?;
            // move to queued
            self.ctx.scheduler.sync_scans().await?;
            // move to running
            self.ctx.scheduler.sync_scans().await?;
            let start = std::time::SystemTime::now();
            loop {
                let response = self.scan_status(&id).await?;
                if response.is_done() {
                    let mut abort = Arc::as_ref(&self.ctx).abort.write().unwrap();
                    *abort = true;
                    return Ok((id, response));
                }

                if let Ok(has_run) = std::time::SystemTime::now().duration_since(start) {
                    let mut abort = Arc::as_ref(&self.ctx).abort.write().unwrap();
                    *abort = true;
                    if has_run.as_secs() > 10 {
                        return Err(scanner::Error::Unexpected(format!(
                            "scan_finish took over {} seconds, aborting",
                            has_run.as_secs()
                        )));
                    }
                }
            }
        }

        pub async fn parsed<'a, T>(
            &self,
            result: HttpResult,
            expected_status: StatusCode,
        ) -> TypeResult<T>
        where
            T: for<'de> Deserialize<'de>,
        {
            let resp = result?;
            if resp.status() != expected_status {
                return Err(scanner::Error::Unexpected(format!(
                    "Expected {} for a body response but got {}",
                    expected_status,
                    resp.status()
                )));
            }

            // infallible
            let resp = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<T>(&resp)
                .map_err(|e| scanner::Error::Unexpected(format!("Unable to serialize: {e}")))
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use http::StatusCode;
    use scannerlib::models::{Scan, VT};

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn results_via_internal_scanner() {
        let client =
            super::client::encrypted_file_based_example_feed("results_via_internal_scanner").await;

        let mut scan: Scan = Scan::default();
        scan.target.hosts.push("localhost".to_string());
        scan.vts = vec![
            VT {
                oid: "0.0.0.0.0.0.0.0.0.3".to_string(),
                parameters: vec![],
            },
            VT {
                oid: "0.0.0.0.0.0.0.0.0.4".to_string(),
                parameters: vec![],
            },
            VT {
                oid: "0.0.0.0.0.0.0.0.0.5".to_string(),
                parameters: vec![],
            },
        ];
        let vts = client.vts().await.unwrap();
        assert!(vts.len() > 2);
        let (id, status) = client.scan_finish(&scan).await.unwrap();
        assert_eq!(status.status, scannerlib::models::Phase::Succeeded);
        let results = client.scan_results(&id, StatusCode::OK).await.unwrap();
        assert_eq!(3, results.len());
        client.scan_delete(&id).await.unwrap();
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn status_of_internal_error_should_be_reflects() {
        let client = super::client::fails_to_fetch_results().await;

        let mut scan: Scan = Scan::default();
        scan.target.hosts.push("localhost".to_string());
        let (id, status) = client.scan_finish(&scan).await.unwrap();
        assert_eq!(status.status, scannerlib::models::Phase::Failed);
        let results = client.scan_results(&id, StatusCode::OK).await.unwrap();
        assert_eq!(0, results.len());
        client.scan_delete(&id).await.unwrap();
    }
}
