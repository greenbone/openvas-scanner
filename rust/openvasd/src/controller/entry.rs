// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines the entry point for the controller.
//!
//! All known paths must be handled in the entrypoint function.

use std::{fmt::Display, sync::Arc};

use super::context::Context;
use hyper::{Body, Method, Request, Response};

use crate::scan::{self, Error, ScanDeleter, ScanStarter, ScanStopper};

enum HealthOpts {
    /// Ready
    Ready,
    /// Started
    Started,
    /// Alive
    Alive,
}
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
    /// /health
    Health(HealthOpts),
    /// /notus/{os}
    Notus(String),
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
            Some("notus") => match parts.next() {
                Some(os) => KnownPaths::Notus(os.to_string()),
                _ => KnownPaths::Unknown,
            },
            Some("health") => match parts.next() {
                Some("ready") => KnownPaths::Health(HealthOpts::Ready),
                Some("alive") => KnownPaths::Health(HealthOpts::Alive),
                Some("started") => KnownPaths::Health(HealthOpts::Started),
                _ => KnownPaths::Unknown,
            },
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
            KnownPaths::Notus(os) => write!(f, "/notus/{}", os),
            KnownPaths::Health(HealthOpts::Alive) => write!(f, "/health/alive"),
            KnownPaths::Health(HealthOpts::Ready) => write!(f, "/health/ready"),
            KnownPaths::Health(HealthOpts::Started) => write!(f, "/health/started"),
        }
    }
}

/// Is used to handle all incomng requests.
///
/// First it will be checked if a known path is requested and if the method is supported.
/// Than corresponding functions will be called to handle the request.
pub async fn entrypoint<'a, S, DB>(
    req: Request<Body>,
    ctx: Arc<Context<S, DB>>,
) -> Result<Response<Body>, Error>
where
    S: ScanStarter
        + ScanStopper
        + ScanDeleter
        + scan::ScanResultFetcher
        + std::marker::Send
        + 'static
        + std::marker::Sync,
    DB: crate::storage::Storage + std::marker::Send + 'static + std::marker::Sync,
{
    use KnownPaths::*;
    // on head requests we just return an empty response without checking the api key
    tracing::trace!(
        "{} {}:{:?}",
        req.method(),
        req.uri().path(),
        req.uri().query()
    );
    if req.method() == Method::HEAD {
        return Ok(ctx.response.empty(hyper::StatusCode::OK));
    }
    let kp = KnownPaths::from_path(req.uri().path());
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
        (&Method::GET, Health(HealthOpts::Alive)) | (&Method::GET, Health(HealthOpts::Started)) => {
            Ok(ctx.response.empty(hyper::StatusCode::OK))
        }
        (&Method::GET, Health(HealthOpts::Ready)) => {
            let oids = ctx.db.oids().await?;
            if oids.count() == 0 {
                Ok(ctx.response.empty(hyper::StatusCode::SERVICE_UNAVAILABLE))
            } else {
                Ok(ctx.response.empty(hyper::StatusCode::OK))
            }
        }
        (&Method::POST, Notus(_os)) => {
            match crate::request::json_request::<models::Advisories>(&ctx.response, req).await {
                // TODO: Call notus module
                Ok(mut _scan) => Ok(ctx.response.empty(hyper::StatusCode::SERVICE_UNAVAILABLE)),
                Err(resp) => Ok(resp),
            }
        }
        (&Method::POST, Scans(None)) => {
            match crate::request::json_request::<models::Scan>(&ctx.response, req).await {
                Ok(mut scan) => {
                    if scan.scan_id.is_some() {
                        return Ok(ctx
                            .response
                            .bad_request("field scan_id is not allowed to be set."));
                    }
                    let id = uuid::Uuid::new_v4().to_string();
                    let resp = ctx.response.created(&id);
                    scan.scan_id = Some(id.clone());
                    ctx.db.insert_scan(scan).await?;
                    tracing::debug!("Scan with ID {} created", &id);
                    Ok(resp)
                }
                Err(resp) => Ok(resp),
            }
        }
        (&Method::POST, Scans(Some(id))) => {
            match crate::request::json_request::<models::ScanAction>(&ctx.response, req)
                .await
                .map(|a| a.action)
            {
                Ok(models::Action::Start) => {
                    let (scan, mut status) = ctx.db.get_decrypted_scan(&id).await?;
                    if status.is_running() {
                        use models::Phase::*;
                        let expected = &[Stored, Stopped, Failed, Succeeded];
                        Ok(ctx.response.not_accepted(&status.status, expected))
                    } else {
                        match ctx.scanner.start_scan(scan).await {
                            Ok(_) => {
                                status.status = models::Phase::Requested;
                                match ctx.db.update_status(&id, status).await {
                                    Ok(_) => Ok(ctx.response.no_content()),
                                    Err(e) => {
                                        let _ = ctx.scanner.stop_scan(id.clone()).await;
                                        let _ = ctx.scanner.delete_scan(id).await;
                                        Ok(ctx.response.internal_server_error(&e))
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Scan with ID {} failed to start: {}", id, e);
                                Ok(ctx.response.internal_server_error(&e))
                            }
                        }
                    }
                }
                Ok(models::Action::Stop) => match ctx.scanner.stop_scan(id).await {
                    Ok(_) => Ok(ctx.response.no_content()),
                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                },
                Err(resp) => Ok(resp),
            }
        }
        (&Method::GET, Scans(None)) => {
            if ctx.enable_get_scans {
                match ctx.db.get_scan_ids().await {
                    Ok(scans) => Ok(ctx.response.ok(&scans)),
                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
                }
            } else {
                Ok(ctx.response.not_found("scans", "all"))
            }
        }
        (&Method::GET, Scans(Some(id))) => match ctx.db.get_scan(&id).await {
            Ok((scan, _)) => Ok(ctx.response.ok(&scan)),
            Err(crate::storage::Error::NotFound) => Ok(ctx.response.not_found("scans", &id)),
            Err(e) => Ok(ctx.response.internal_server_error(&e)),
        },
        (&Method::GET, ScanStatus(id)) => match ctx.db.get_scan(&id).await {
            Ok((_, status)) => Ok(ctx.response.ok(&status)),
            Err(crate::storage::Error::NotFound) => Ok(ctx.response.not_found("scans/status", &id)),
            Err(e) => Ok(ctx.response.internal_server_error(&e)),
        },
        (&Method::DELETE, Scans(Some(id))) => match ctx.db.get_status(&id).await {
            Ok(status) => {
                if status.is_running() {
                    ctx.scanner.stop_scan(id.clone()).await?;
                }
                ctx.db.remove_scan(&id).await?;
                ctx.scanner.delete_scan(id).await?;
                Ok(ctx.response.no_content())
            }
            Err(crate::storage::Error::NotFound) => Ok(ctx.response.not_found("scans", &id)),
            Err(e) => Err(e.into()),
        },
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

            match ctx.db.get_results(&id, begin, end).await {
                Ok(results) => Ok(ctx.response.ok_byte_stream(results).await),
                Err(crate::storage::Error::NotFound) => {
                    Ok(ctx.response.not_found("scans/results", &id))
                }
                Err(e) => Ok(ctx.response.internal_server_error(&e)),
            }
        }

        (&Method::GET, Vts) => {
            let oids = ctx.db.oids().await?;

            Ok(ctx.response.ok_json_stream(oids).await)
        }
        _ => Ok(ctx.response.not_found("path", req.uri().path())),
    }
}
