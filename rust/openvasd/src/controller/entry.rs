// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines the entry point for the controller.
//!
//! All known paths must be handled in the entrypoint function.

use std::{fmt::Display, marker::PhantomData, sync::Arc};

use super::{context::Context, ClientIdentifier};

use hyper::{Method, Request};
use models::scanner::{ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper};

use crate::{
    config,
    controller::ClientHash,
    notus::NotusScanner,
    scheduling,
    storage::{NVTStorer as _, ProgressGetter as _, ScanIDClientMapper as _, ScanStorer as _},
};
use models::scanner::*;

enum HealthOpts {
    /// Ready
    Ready,
    /// Started
    Started,
    /// Alive
    Alive,
}
/// The supported paths of openvasd
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
                    tracing::debug!(?mode, ?path, "Scan endpoint enabled");
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
            KnownPaths::Scans(Some(id)) => write!(f, "/scans/{}", id),
            KnownPaths::Scans(None) => write!(f, "/scans"),
            KnownPaths::ScanResults(id, Some(result_id)) => {
                write!(f, "/scans/{}/results/{}", id, result_id)
            }
            KnownPaths::ScanResults(id, None) => write!(f, "/scans/{}/results", id),
            KnownPaths::ScanStatus(id) => write!(f, "/scans/{}/status", id),
            KnownPaths::Unknown => write!(f, "Unknown"),
            KnownPaths::Vts(None) => write!(f, "/vts"),
            KnownPaths::Vts(Some(oid)) => write!(f, "/vts/{oid}"),
            KnownPaths::Notus(Some(os)) => write!(f, "/notus/{}", os),
            KnownPaths::Notus(None) => write!(f, "/notus"),
            KnownPaths::Health(HealthOpts::Alive) => write!(f, "/health/alive"),
            KnownPaths::Health(HealthOpts::Ready) => write!(f, "/health/ready"),
            KnownPaths::Health(HealthOpts::Started) => write!(f, "/health/started"),
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
            // on head requests we just return an empty response without checking the api key
            if req.method() == Method::HEAD {
                return Ok(ctx.response.empty(hyper::StatusCode::OK));
            }
            let kp = KnownPaths::from_path(req.uri().path(), &ctx.mode);
            let cid: Option<ClientHash> = {
                match &*cid {
                    ClientIdentifier::Disabled => {
                        if let Some(key) = ctx.api_key.as_ref() {
                            match req.headers().get("x-api-key") {
                                Some(v) if v == key => ctx.api_key.as_ref().map(|x| x.into()),
                                Some(v) => {
                                    tracing::debug!("{} {} invalid key: {:?}", req.method(), kp, v);
                                    None
                                }
                                None => None,
                            }
                        } else {
                            Some("disabled".into())
                        }
                    }
                    ClientIdentifier::Known(cid) => Some(cid.clone()),
                    ClientIdentifier::Unknown => {
                        if let Some(key) = ctx.api_key.as_ref() {
                            match req.headers().get("x-api-key") {
                                Some(v) if v == key => ctx.api_key.as_ref().map(|x| x.into()),
                                Some(v) => {
                                    tracing::debug!("{} {} invalid key: {:?}", req.method(), kp, v);
                                    None
                                }
                                None => None,
                            }
                        } else {
                            // We don't allow no api key and no client certs when we have a server
                            // certificate to prevent accidental misconfiguration.
                            None
                        }
                    }
                }
            };

            if kp.requires_id() && cid.is_none() {
                tracing::debug!("{} {} unauthorized", req.method(), kp);
                return Ok(ctx.response.unauthorized());
            }
            let cid = cid.unwrap_or_default();
            if let Some(scan_id) = kp.scan_id() {
                if !ctx
                    .scheduler
                    .is_client_allowed(scan_id.to_owned(), &cid)
                    .await
                    .unwrap()
                {
                    tracing::debug!(
                        "client {:x?} is not allowed to operate on scan {} ",
                        &cid.0,
                        scan_id
                    );
                    // we return 404 instead of 401 to not leak any ids
                    return Ok(ctx.response.not_found("scans", scan_id));
                }
            }

            tracing::debug!(
                method=%req.method(),
                path=req.uri().path(),
                query=req.uri().query(),
                "process call",
            );
            match (req.method(), kp) {
                (&Method::GET, Health(HealthOpts::Alive))
                | (&Method::GET, Health(HealthOpts::Started)) => {
                    Ok(ctx.response.empty(hyper::StatusCode::OK))
                }
                (&Method::GET, Health(HealthOpts::Ready)) => {
                    let oids = ctx.scheduler.oids().await?;
                    if oids.count() == 0 {
                        Ok(ctx.response.empty(hyper::StatusCode::SERVICE_UNAVAILABLE))
                    } else {
                        Ok(ctx.response.empty(hyper::StatusCode::OK))
                    }
                }
                (&Method::GET, Notus(None)) => match &ctx.notus {
                    Some(notus) => match notus.get_available_os().await {
                        Ok(result) => Ok(ctx.response.ok(&result)),
                        Err(err) => Ok(ctx.response.internal_server_error(&err)),
                    },
                    None => Ok(ctx.response.empty(hyper::StatusCode::SERVICE_UNAVAILABLE)),
                },

                (&Method::POST, Notus(Some(os))) => {
                    match crate::request::json_request::<Vec<String>, _>(&ctx.response, req).await {
                        Ok(packages) => match &ctx.notus {
                            Some(notus) => match notus.scan(&os, &packages).await {
                                Ok(results) => Ok(ctx.response.ok(&results)),
                                Err(err) => match err {
                                    notus::error::Error::UnknownProduct(_) => {
                                        Ok(ctx.response.not_found("advisories", &os))
                                    }
                                    notus::error::Error::PackageParseError(_) => {
                                        Ok(ctx.response.bad_request(&format!("{err}")))
                                    }
                                    _ => Ok(ctx.response.internal_server_error(&err)),
                                },
                            },
                            None => Ok(ctx.response.empty(hyper::StatusCode::SERVICE_UNAVAILABLE)),
                        },
                        Err(resp) => Ok(resp),
                    }
                }
                (&Method::POST, Scans(None)) => {
                    match crate::request::json_request::<models::Scan, _>(&ctx.response, req).await
                    {
                        Ok(mut scan) => {
                            if !scan.scan_id.is_empty() {
                                return Ok(ctx
                                    .response
                                    .bad_request("field scan_id is not allowed to be set."));
                            }
                            let id = uuid::Uuid::new_v4().to_string();
                            let resp = ctx.response.created(&id);
                            scan.scan_id.clone_from(&id);
                            ctx.scheduler.insert_scan(scan).await?;
                            ctx.scheduler.add_scan_client_id(id.clone(), cid).await?;
                            tracing::debug!(%id, "Scan created");
                            Ok(resp)
                        }
                        Err(resp) => Ok(resp),
                    }
                }
                (&Method::POST, Scans(Some(id))) => {
                    match crate::request::json_request::<models::ScanAction, _>(&ctx.response, req)
                        .await
                        .map(|a| a.action)
                    {
                        Ok(models::Action::Start) => {
                            match ctx.scheduler.start_scan_by_id(&id).await {
                                Ok(_) => Ok(ctx.response.no_content()),
                                Err(scheduling::Error::ScanRunning)
                                | Err(scheduling::Error::ScanAlreadyQueued) => {
                                    use models::Phase::*;
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
                        Ok(models::Action::Stop) => match ctx.scheduler.stop_scan(id).await {
                            Ok(_) => Ok(ctx.response.no_content()),
                            Err(e) => Ok(ctx.response.internal_server_error(&e)),
                        },
                        Err(resp) => Ok(resp),
                    }
                }
                (&Method::GET, Scans(None)) => {
                    if ctx.enable_get_scans {
                        match ctx.scheduler.get_scans_of_client_id(&cid).await {
                            Ok(scans) => Ok(ctx.response.ok(&scans)),
                            Err(e) => Ok(ctx.response.internal_server_error(&e)),
                        }
                    } else {
                        Ok(ctx.response.not_found("scans", "all"))
                    }
                }
                (&Method::GET, ScanPreferences) => Ok(ctx
                    .response
                    .ok_static(crate::preference::PREFERENCES_JSON.as_bytes())),
                (&Method::GET, Scans(Some(id))) => match ctx.scheduler.get_scan(&id).await {
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
                        Ok(ctx.response.not_found("scans", &id))
                    }
                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                },
                (&Method::GET, ScanStatus(id)) => match ctx.scheduler.get_scan(&id).await {
                    Ok((_, status)) => Ok(ctx.response.ok(&status)),
                    Err(crate::storage::Error::NotFound) => {
                        Ok(ctx.response.not_found("scans/status", &id))
                    }
                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                },
                (&Method::DELETE, Scans(Some(id))) => {
                    match ctx.scheduler.delete_scan_by_id(&id).await {
                        Ok(_) => Ok(ctx.response.no_content()),
                        Err(crate::scheduling::Error::NotFound) => {
                            Ok(ctx.response.not_found("scans", &id))
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                (&Method::GET, ScanResults(id, rid)) => {
                    let (begin, end) = {
                        if let Some(id) = rid {
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

                    match ctx.scheduler.get_results(&id, begin, end).await {
                        Ok(results) => Ok(ctx.response.ok_byte_stream(results).await),
                        Err(crate::storage::Error::NotFound) => {
                            Ok(ctx.response.not_found("scans/results", &id))
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
                        None if meta => Ok(ctx
                            .response
                            .ok_json_stream(ctx.scheduler.vts().await?)
                            .await),
                        None => Ok(ctx
                            .response
                            .ok_json_stream(ctx.scheduler.oids().await?)
                            .await),
                    }
                }
                _ => Ok(ctx.response.not_found("path", req.uri().path())),
            }
        })
    }
}
