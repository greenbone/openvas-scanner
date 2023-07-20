// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod context;
mod entry;
pub mod feed;
pub mod results;

use crate::scan::{ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper};
pub use context::{Context, ContextBuilder, NoOpScanner};
pub use entry::entrypoint;

/// Quits application on an poisoned lock.
pub(crate) fn quit_on_poison<T>() -> T {
    tracing::error!("exit because of poisoned lock");
    std::process::exit(1);
}

/// Combines all traits needed for a scanner.
pub trait Scanner: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher {}

impl<T> Scanner for T where T: Send + ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher {}

macro_rules! make_svc {
    ($controller:expr) => {{
        // start background service
        use std::sync::Arc;
        tokio::spawn(crate::controller::results::fetch(Arc::clone(&$controller)));
        tokio::spawn(crate::controller::feed::fetch(Arc::clone(&$controller)));

        use hyper::service::{make_service_fn, service_fn};
        make_service_fn(|_conn| {
            let controller = Arc::clone($controller);
            async {
                Ok::<_, crate::scan::Error>(service_fn(move |req| {
                    crate::controller::entrypoint(req, Arc::clone(&controller))
                }))
            }
        })
    }};
}

pub(crate) use make_svc;

#[cfg(test)]
mod tests {
    use super::context::Context;
    use super::entry::entrypoint;
    use crate::{
        controller::{ContextBuilder, NoOpScanner},
        scan::Progress,
    };
    use hyper::{Body, Method, Request, Response};
    use std::sync::{Arc, RwLock};

    use crate::scan::{ScanDeleter, ScanStarter, ScanStopper};

    #[derive(Debug, Clone)]
    struct FakeScanner {
        count: Arc<RwLock<usize>>,
    }

    impl crate::scan::ScanStarter for FakeScanner {
        fn start_scan(&self, _scan: &Progress) -> Result<(), crate::scan::Error> {
            Ok(())
        }
    }

    impl crate::scan::ScanStopper for FakeScanner {
        fn stop_scan(&self, _scan: &Progress) -> Result<(), crate::scan::Error> {
            Ok(())
        }
    }

    impl crate::scan::ScanDeleter for FakeScanner {
        fn delete_scan(&self, _scan: &Progress) -> Result<(), crate::scan::Error> {
            Ok(())
        }
    }

    impl crate::scan::ScanResultFetcher for FakeScanner {
        fn fetch_results(
            &self,
            prgrs: &crate::scan::Progress,
        ) -> Result<crate::scan::FetchResult, crate::scan::Error> {
            let mut count = self.count.write().unwrap();
            match *count {
                0 => {
                    let status = models::Status {
                        status: models::Phase::Requested,
                        ..Default::default()
                    };
                    *count += 1;
                    Ok((status, vec![]))
                }
                1..=99 => {
                    let status = models::Status {
                        status: models::Phase::Running,
                        ..Default::default()
                    };
                    let mut results = vec![];
                    for i in 0..*count {
                        results.push(models::Result {
                            id: prgrs.results.len() + i,
                            message: Some(uuid::Uuid::new_v4().to_string()),
                            ..Default::default()
                        });
                    }
                    *count += 1;
                    Ok((status, results))
                }
                _ => {
                    *count += 1;
                    let status = models::Status {
                        status: models::Phase::Succeeded,
                        ..Default::default()
                    };
                    Ok((status, vec![]))
                }
            }
        }
    }

    #[tokio::test]
    async fn contains_version() {
        let controller = Arc::new(Context::default());
        let req = Request::builder()
            .method(Method::HEAD)
            .body(Body::empty())
            .unwrap();
        let resp = entrypoint(req, Arc::clone(&controller)).await.unwrap();
        assert_eq!(resp.headers().get("api-version").unwrap(), "1");
        assert_eq!(resp.headers().get("authentication").unwrap(), "");
    }
    async fn get_scan_status<S>(id: &str, ctx: Arc<Context<S>>) -> Response<Body>
    where
        S: ScanStarter
            + ScanStopper
            + ScanDeleter
            + std::marker::Send
            + 'static
            + std::marker::Sync
            + std::fmt::Debug,
    {
        let req = Request::builder()
            .uri(format!("/scans/{id}/status", id = id))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        entrypoint(req, Arc::clone(&ctx)).await.unwrap()
    }

    async fn get_scan<S>(id: &str, ctx: Arc<Context<S>>) -> Response<Body>
    where
        S: ScanStarter
            + ScanStopper
            + ScanDeleter
            + std::marker::Send
            + 'static
            + std::marker::Sync
            + std::fmt::Debug,
    {
        let req = Request::builder()
            .uri(format!("/scans/{id}", id = id))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        entrypoint(req, Arc::clone(&ctx)).await.unwrap()
    }

    async fn post_scan<S>(scan: &models::Scan, ctx: Arc<Context<S>>) -> Response<Body>
    where
        S: ScanStarter
            + ScanStopper
            + ScanDeleter
            + std::marker::Send
            + 'static
            + std::marker::Sync
            + std::fmt::Debug,
    {
        let req = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        entrypoint(req, Arc::clone(&ctx)).await.unwrap()
    }

    async fn start_scan<S>(id: &str, ctx: Arc<Context<S>>) -> Response<Body>
    where
        S: ScanStarter
            + ScanStopper
            + ScanDeleter
            + std::marker::Send
            + 'static
            + std::marker::Sync
            + std::fmt::Debug,
    {
        let action = &models::ScanAction {
            action: models::Action::Start,
        };
        let req = Request::builder()
            .uri(format!("/scans/{id}", id = id))
            .method(Method::POST)
            .body(serde_json::to_string(action).unwrap().into())
            .unwrap();
        entrypoint(req, Arc::clone(&ctx)).await.unwrap()
    }

    async fn post_scan_id<S>(scan: &models::Scan, ctx: Arc<Context<S>>) -> String
    where
        S: ScanStarter
            + ScanStopper
            + ScanDeleter
            + std::marker::Send
            + 'static
            + std::marker::Sync
            + std::fmt::Debug,
    {
        let resp = post_scan(scan, Arc::clone(&ctx)).await;
        let resp = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let resp = String::from_utf8(resp.to_vec()).unwrap();
        let id = resp.trim_matches('"');
        id.to_string()
    }

    #[tokio::test]
    async fn add_scan() {
        let scan: models::Scan = models::Scan::default();
        let controller = Arc::new(Context::default());
        let id = post_scan_id(&scan, Arc::clone(&controller)).await;
        let resp = get_scan(&id, Arc::clone(&controller)).await;
        let resp = hyper::body::to_bytes(resp.into_body()).await.unwrap();

        let resp = serde_json::from_slice::<models::Scan>(&resp).unwrap();

        let scan: models::Scan = models::Scan {
            scan_id: Some(id.to_string()),
            ..Default::default()
        };
        assert_eq!(resp, scan);
    }

    #[tokio::test]
    async fn delete_scan() {
        let scan: models::Scan = models::Scan::default();
        let controller = Arc::new(Context::default());
        let id = post_scan_id(&scan, Arc::clone(&controller)).await;
        let resp = get_scan(&id, Arc::clone(&controller)).await;
        assert_eq!(resp.status(), 200);
        let req = Request::builder()
            .uri(format!("/scans/{id}"))
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        entrypoint(req, Arc::clone(&controller)).await.unwrap();
        let resp = get_scan(&id, Arc::clone(&controller)).await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn fetch_results() {
        let scan: models::Scan = models::Scan::default();
        let scanner = FakeScanner {
            count: Arc::new(RwLock::new(0)),
        };
        let ns = std::time::Duration::from_nanos(10);
        let ctx = ContextBuilder::new()
            .result_config(ns)
            .scanner(scanner)
            .build();
        let controller = Arc::new(ctx);

        tokio::spawn(crate::controller::results::fetch(Arc::clone(&controller)));
        let id = post_scan_id(&scan, Arc::clone(&controller)).await;
        let resp = start_scan(&id, Arc::clone(&controller)).await;
        assert_eq!(resp.status(), 204);
        loop {
            let resp = get_scan_status(&id, Arc::clone(&controller)).await;
            assert_eq!(resp.status(), 200);

            let resp = hyper::body::to_bytes(resp.into_body()).await.unwrap();
            let resp = serde_json::from_slice::<models::Status>(&resp).unwrap();
            // would run into an endlessloop if the scan would never finish
            if resp.status == models::Phase::Succeeded {
                let mut abort = Arc::as_ref(&controller).abort.write().unwrap();
                *abort = true;
                break;
            }
        }
    }

    #[tokio::test]
    async fn unauthorized() {
        let scan: models::Scan = models::Scan::default();
        let ctx = ContextBuilder::new()
            .api_key(Some("mtls_is_preferred".to_string()))
            .scanner(NoOpScanner::default())
            .build();
        let controller = Arc::new(ctx);
        let resp = post_scan(&scan, Arc::clone(&controller)).await;
        assert_eq!(resp.status(), 401);
        let req = Request::builder()
            .uri("/scans")
            .header("X-API-KEY", "mtls_is_preferred")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let resp = entrypoint(req, Arc::clone(&controller)).await.unwrap();
        assert_eq!(resp.status(), 201);
    }
}
