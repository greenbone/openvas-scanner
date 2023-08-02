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
    let kp = KnownPaths::from_path(req.uri().path());
    tracing::debug!("{} {}", req.method(), kp);
    // on head requests we just return an empty response without checking the api key
    if req.method() == Method::HEAD {
        return Ok(ctx.response.empty(hyper::StatusCode::OK));
    }
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
        (&Method::POST, Scans(None)) => {
            match crate::request::json_request::<models::Scan>(&ctx.response, req).await {
                Ok(mut scan) => {
                    if scan.scan_id.is_none() {
                        scan.scan_id = Some(uuid::Uuid::new_v4().to_string());
                    }
                    let id = scan.scan_id.clone().unwrap_or_default();
                    let resp = ctx.response.created(&id);
                    ctx.db.insert_scan(scan).await?;
                    tracing::debug!("Scan with ID {} created", id);
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
                                    Err(e) => Ok(ctx.response.internal_server_error(&e)),
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
                match ctx.db.get_scans().await {
                    Ok(scans) => Ok(ctx.response.ok(&scans
                        .into_iter()
                        .map(|s| s.0.scan_id.unwrap_or_default())
                        .collect::<Vec<_>>())),
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
        (&Method::DELETE, Scans(Some(id))) => match ctx.db.remove_scan(&id).await? {
            Some((_, status)) => {
                if status.is_running() {
                    ctx.scanner.stop_scan(id.clone()).await?;
                }
                ctx.scanner.delete_scan(id).await?;
                Ok(ctx.response.no_content())
            }
            None => Ok(ctx.response.not_found("scans", &id)),
        },
        (&Method::GET, ScanResults(id, _rid)) => match ctx.db.get_results(&id, None, None).await {
            Ok(results) => Ok(ctx.response.ok(&results)),
            Err(crate::storage::Error::NotFound) => {
                Ok(ctx.response.not_found("scans/results", &id))
            }
            Err(e) => Ok(ctx.response.internal_server_error(&e)),
        },

        (&Method::GET, Vts) => {
            let (_, oids) = ctx.oids.read()?.clone();
            Ok(ctx.response.ok_stream(oids).await)
        }
        _ => Ok(ctx.response.not_found("path", req.uri().path())),
    }
}
