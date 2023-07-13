// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines the entry point for the controller.
//!
//! All known paths must be handled in the entrypoint function.

use std::{fmt::Display, sync::Arc};

use super::{context::Context, quit_on_poison};
use hyper::{Body, Method, Request, Response};

use crate::scan::{Error, ScanDeleter, ScanStarter, ScanStopper};
/// The supported paths of scannerd
enum KnownPaths {
    /// /scans/{id}
    Scans(Option<String>),
    /// /scans/{id}/results/{result_id}
    ScanResults(String, Option<String>),
    /// /scans/{id}/status
    ScanStatus(String),
    /// /vts
    Vts,
    /// Not supported
    Unknown,
}

impl KnownPaths {
    #[tracing::instrument]
    /// Parses a path and returns the corresponding `KnownPaths` variant.
    fn from_path(path: &str) -> Self {
        let mut parts = path.split('/').filter(|s| !s.is_empty());
        match parts.next() {
            Some("scans") => match parts.next() {
                Some(id) => match parts.next() {
                    Some("results") => {
                        KnownPaths::ScanResults(id.to_string(), parts.next().map(|s| s.to_string()))
                    }
                    Some("status") => KnownPaths::ScanStatus(id.to_string()),
                    Some(_) => KnownPaths::Unknown,
                    None => KnownPaths::Scans(Some(id.to_string())),
                },
                None => KnownPaths::Scans(None),
            },
            Some("vts") => KnownPaths::Vts,
            _ => {
                tracing::trace!("Unknown path: {path}");
                KnownPaths::Unknown
            }
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
            KnownPaths::Vts => write!(f, "/vts"),
        }
    }
}

/// Is used to call a blocking function and return a response.
///
/// This is necessary as the ospd library is blocking and when blocking calls
/// are made in a tokio the complete thread will be blocked.
///
/// To give tokio the chance to handle the blocking call appropriately it is
/// wrapped within a tokio::task::spawn_blocking call.
///
/// If the thread panics a 500 response is returned.
async fn response_blocking<F>(f: F) -> Result<Response<Body>, Error>
where
    F: FnOnce() -> Result<Response<Body>, Error> + std::marker::Send + 'static,
{
    Ok(match tokio::task::spawn_blocking(f).await {
        Ok(Ok(r)) => r,
        Ok(Err(Error::Poisoned)) => quit_on_poison(),
        Ok(Err(e)) => {
            tracing::warn!("unhandled error: {:?} returning 500", e);
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(hyper::Body::empty())
                .unwrap()
        }
        Err(e) => {
            tracing::warn!("panic {:?}, returning 500", e);
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(hyper::Body::empty())
                .unwrap()
        }
    })
}

/// Is used to handle all incomng requests.
///
/// First it will be checked if a known path is requested and if the method is supported.
/// Than corresponding functions will be called to handle the request.
pub async fn entrypoint<'a, S>(
    req: Request<Body>,
    ctx: Arc<Context<S>>,
) -> Result<Response<Body>, Error>
where
    S: ScanStarter
        + ScanStopper
        + ScanDeleter
        + std::marker::Send
        + 'static
        + std::marker::Sync
        + std::fmt::Debug,
{
    use KnownPaths::*;
    let kp = KnownPaths::from_path(req.uri().path());
    tracing::debug!("{} {}", req.method(), kp);
    if let Some(key) = ctx.api_key.as_ref() {
        match req.headers().get("x-api-key") {
            Some(v) if v == key => {}
            Some(v) => {
                tracing::debug!("{} {} invalid key: {:?}", req.method(), kp, v);
                return Ok(ctx.response.unauthorized());
            }
            _ => {
                tracing::debug!("{} {} unauthorized", req.method(), kp);
                return Ok(ctx.response.unauthorized());
            }
        }
    }

    match (req.method(), kp) {
        (&Method::HEAD, _) => Ok(ctx.response.empty(hyper::StatusCode::OK)),
        (&Method::POST, Scans(None)) => {
            match crate::request::json_request::<models::Scan>(&ctx.response, req).await {
                Ok(mut scan) => {
                    response_blocking(move || {
                        if scan.scan_id.is_none() {
                            scan.scan_id = Some(uuid::Uuid::new_v4().to_string());
                        }
                        let mut scans = ctx.scans.write()?;
                        let id = scan.scan_id.clone().unwrap_or_default();
                        let resp = ctx.response.created(&id);
                        scans.insert(id.clone(), crate::scan::Progress::from(scan));
                        tracing::debug!("Scan with ID {} created", id);
                        Ok(resp)
                    })
                    .await
                }
                Err(resp) => Ok(resp),
            }
        }
        (&Method::POST, Scans(Some(id))) => {
            match crate::request::json_request::<models::ScanAction>(&ctx.response, req).await {
                Ok(action) => {
                    response_blocking(move || {
                        let mut scans = ctx.scans.write()?;
                        match (action.action, scans.get_mut(&id)) {
                            (models::Action::Start, Some(progress))
                                if progress.status.is_running() =>
                            {
                                use models::Phase::*;
                                let expected = &[Stored, Stopped, Failed, Succeeded];
                                Ok(ctx.response.not_accepted(&progress.status.status, expected))
                            }
                            (models::Action::Start, Some(progress)) => {
                                tracing::debug!(
                                    "{}: {}",
                                    progress.scan.scan_id.as_ref().unwrap_or(&"".to_string()),
                                    action.action,
                                );

                                match ctx.scanner.start_scan(progress) {
                                    Ok(()) => {
                                        progress.status.status = models::Phase::Requested;
                                        tracing::debug!(
                                            "Scan with ID {} started",
                                            progress
                                                .scan
                                                .scan_id
                                                .as_ref()
                                                .unwrap_or(&"".to_string())
                                        );
                                        Ok(ctx.response.no_content())
                                    }
                                    // TODO we need to parse the ospd response for status code
                                    Err(e) => {
                                        tracing::debug!(
                                            "Unable to start Scan with ID {}",
                                            progress
                                                .scan
                                                .scan_id
                                                .as_ref()
                                                .unwrap_or(&"".to_string())
                                        );
                                        match e {
                                            Error::SocketDoesNotExist(path) => {
                                                Ok(ctx.response.service_unavailable(
                                                    "OSP",
                                                    format!(
                                                        "socket {} does not exist",
                                                        path.display()
                                                    )
                                                    .as_str(),
                                                ))
                                            }
                                            _ => Ok(ctx.response.internal_server_error(&e)),
                                        }
                                    }
                                }
                            }
                            (models::Action::Stop, Some(progress)) => {
                                tracing::debug!(
                                    "{}: {}",
                                    progress.scan.scan_id.as_ref().unwrap_or(&"".to_string()),
                                    action.action,
                                );
                                match ctx.scanner.stop_scan(progress) {
                                    Ok(()) => Ok(ctx.response.no_content()),
                                    // TODO we need to parse the ospd response for status code
                                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                                }
                            }
                            (_, None) => Ok(ctx.response.not_found("scans", &id)),
                        }
                    })
                    .await
                }
                Err(resp) => Ok(resp),
            }
        }
        (&Method::GET, Scans(None)) => {
            if ctx.enable_get_scans {
                response_blocking(move || {
                    let scans = ctx.scans.read()?;
                    Ok(ctx.response.ok(&scans.keys().collect::<Vec<_>>()))
                })
                .await
            } else {
                Ok(ctx.response.not_found("scans", "all"))
            }
        }
        (&Method::GET, Scans(Some(id))) => {
            response_blocking(move || {
                let scans = ctx.scans.read()?;
                match scans.get(&id) {
                    Some(prgrs) => Ok(ctx.response.ok(&prgrs.scan)),
                    None => Ok(ctx.response.not_found("scans", &id)),
                }
            })
            .await
        }
        (&Method::GET, ScanStatus(id)) => {
            response_blocking(move || {
                let scans = ctx.scans.read()?;
                match scans.get(&id) {
                    Some(prgrs) => Ok(ctx.response.ok(&prgrs.status)),
                    None => Ok(ctx.response.not_found("scans/status", &id)),
                }
            })
            .await
        }
        (&Method::DELETE, Scans(Some(id))) => {
            response_blocking(move || {
                let mut scans = ctx.scans.write()?;
                match scans.remove(&id) {
                    Some(s) => {
                        if s.status.is_running() {
                            ctx.scanner.stop_scan(&s)?;
                        }
                        ctx.scanner.delete_scan(&s)?;
                        Ok(ctx.response.no_content())
                    }
                    None => Ok(ctx.response.not_found("scans", &id)),
                }
            })
            .await
        }
        (&Method::GET, ScanResults(id, _rid)) => {
            response_blocking(move || {
                let scans = ctx.scans.read()?;
                match scans.get(&id) {
                    Some(prgrs) => Ok(ctx.response.ok(&prgrs.results)),
                    None => Ok(ctx.response.not_found("scans", &id)),
                }
            })
            .await
        }
        (&Method::GET, Vts) => {
            let (_, oids) = ctx.oids.read()?.clone();
            Ok(ctx.response.ok_stream(oids).await)
        }
        _ => Ok(ctx.response.not_found("path", req.uri().path())),
    }
}
