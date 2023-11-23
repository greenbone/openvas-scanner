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

#[derive(Clone, Default, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientHash([u8; 32]);

impl<T> From<T> for ClientHash
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(value);
        let hash = hasher.finalize();
        Self(hash.into())
    }
}

/// Contains information about an authorization model of a connection (e.g. mtls)
#[derive(Default, Debug)]
pub enum ClientIdentifier {
    /// When there in no information available
    #[default]
    Unknown,
    /// Contains a hashed number of an identifier
    ///
    /// openvasd uses the identifier as a key for results. This key is usually calculated by an
    /// subject of a known client certificate. Based on that we don't need more information.
    Known(ClientHash),
}
/// Is used to transfer the information if there is an identifier present within the connection
pub trait ClientGossiper {
    /// Gets the identifier
    ///
    /// Based on the concurrent nature, the actual information is boxed within a Arc and locked for
    /// concurrent read write accesses.
    fn client_identifier(&self) -> &std::sync::Arc<std::sync::RwLock<ClientIdentifier>>;
}

impl<T> Scanner for T where T: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher {}

#[cfg(test)]
mod tests {
    use super::context::Context;
    use super::entry::entrypoint;
    use crate::{
        controller::{ClientIdentifier, ContextBuilder, NoOpScanner},
        storage::file,
    };
    use async_trait::async_trait;
    use hyper::{Body, Method, Request, Response};
    use infisto::base::IndexedFileStorer;
    use std::sync::{Arc, RwLock};

    #[derive(Debug, Clone)]
    struct FakeScanner {
        count: Arc<RwLock<usize>>,
    }

    #[async_trait]
    impl crate::scan::ScanStarter for FakeScanner {
        async fn start_scan(&self, _scan: models::Scan) -> Result<(), crate::scan::Error> {
            Ok(())
        }
    }

    #[async_trait]
    impl crate::scan::ScanStopper for FakeScanner {
        async fn stop_scan<I>(&self, _id: I) -> Result<(), crate::scan::Error>
        where
            I: AsRef<str> + Send,
        {
            Ok(())
        }
    }

    #[async_trait]
    impl crate::scan::ScanDeleter for FakeScanner {
        async fn delete_scan<I>(&self, _id: I) -> Result<(), crate::scan::Error>
        where
            I: AsRef<str> + Send,
        {
            Ok(())
        }
    }

    #[async_trait]
    impl crate::scan::ScanResultFetcher for FakeScanner {
        async fn fetch_results<I>(
            &self,
            _id: I,
        ) -> Result<crate::scan::FetchResult, crate::scan::Error>
        where
            I: AsRef<str> + Send,
        {
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
                            id: i,
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
        let cid = Arc::new(RwLock::new(ClientIdentifier::Unknown));
        let resp = entrypoint(req, Arc::clone(&controller), cid).await.unwrap();
        assert_eq!(resp.headers().get("api-version").unwrap(), "1");
        assert_eq!(resp.headers().get("authentication").unwrap(), "");
    }

    async fn get_scan_status<S, DB>(id: &str, ctx: Arc<Context<S, DB>>) -> Response<Body>
    where
        S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let req = Request::builder()
            .uri(format!("/scans/{id}/status", id = id))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let cid = Arc::new(RwLock::new(ClientIdentifier::Known("42".into())));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn get_scan<S, DB>(id: &str, ctx: Arc<Context<S, DB>>) -> Response<Body>
    where
        S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let req = Request::builder()
            .uri(format!("/scans/{id}", id = id))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let cid = Arc::new(RwLock::new(ClientIdentifier::Known("42".into())));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn post_scan<S, DB>(scan: &models::Scan, ctx: Arc<Context<S, DB>>) -> Response<Body>
    where
        S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let req = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let cid = Arc::new(RwLock::new(ClientIdentifier::Known("42".into())));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn start_scan<S, DB>(id: &str, ctx: Arc<Context<S, DB>>) -> Response<Body>
    where
        S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let action = &models::ScanAction {
            action: models::Action::Start,
        };
        let req = Request::builder()
            .uri(format!("/scans/{id}", id = id))
            .method(Method::POST)
            .body(serde_json::to_string(action).unwrap().into())
            .unwrap();
        let cid = Arc::new(RwLock::new(ClientIdentifier::Known("42".into())));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn post_scan_id<S, DB>(scan: &models::Scan, ctx: Arc<Context<S, DB>>) -> String
    where
        S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let resp = post_scan(scan, Arc::clone(&ctx)).await;
        let resp = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let resp = String::from_utf8(resp.to_vec()).unwrap();
        let id = resp.trim_matches('"');
        id.to_string()
    }

    #[tokio::test]
    async fn add_scan_with_id_fails() {
        let scan: models::Scan = models::Scan {
            scan_id: Some(String::new()),
            ..Default::default()
        };
        let ctx = Arc::new(Context::default());
        let resp = post_scan(&scan, Arc::clone(&ctx)).await;
        assert_eq!(resp.status(), hyper::http::StatusCode::BAD_REQUEST);
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
        let cid = Arc::new(RwLock::new(ClientIdentifier::Known("42".into())));
        entrypoint(req, Arc::clone(&controller), cid).await.unwrap();
        let resp = get_scan(&id, Arc::clone(&controller)).await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn fetch_results() {
        async fn get_results<S, DB>(
            id: &str,
            ctx: Arc<Context<S, DB>>,
            idx: Option<usize>,
            range: Option<(usize, usize)>,
        ) -> Vec<models::Result>
        where
            S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
            DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
        {
            let uri = match idx {
                Some(idx) => format!("/scans/{id}/results/{idx}"),
                None => {
                    if let Some((begin, end)) = range {
                        format!("/scans/{id}/results?range={begin}-{end}")
                    } else {
                        format!("/scans/{id}/results")
                    }
                }
            };
            let req = Request::builder()
                .uri(uri)
                .method(Method::GET)
                .body(Body::empty())
                .unwrap();
            let cid = Arc::new(RwLock::new(ClientIdentifier::Known("42".into())));
            let resp = entrypoint(req, Arc::clone(&ctx), cid).await.unwrap();
            let resp = hyper::body::to_bytes(resp.into_body()).await.unwrap();

            serde_json::from_slice::<Vec<models::Result>>(&resp).unwrap()
        }
        let scan: models::Scan = models::Scan::default();
        let scanner = FakeScanner {
            count: Arc::new(RwLock::new(0)),
        };
        let ns = std::time::Duration::from_nanos(10);
        let root = "/tmp/openvasd/fetch_results";
        let storage = file::unencrypted(root).unwrap();
        let ctx = ContextBuilder::new()
            .result_config(ns)
            .storage(storage)
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
        let mut resp = get_results(&id, Arc::clone(&controller), None, None).await;
        resp.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(resp.len(), 4950);
        resp.iter().enumerate().for_each(|(i, r)| {
            assert_eq!(r.id, i);
        });
        let resp = get_results(&id, Arc::clone(&controller), Some(0), None).await;
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].id, 0);
        let resp = get_results(&id, Arc::clone(&controller), Some(4949), None).await;
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].id, 4949);
        let mut resp = get_results(&id, Arc::clone(&controller), None, Some((4900, 4923))).await;
        assert_eq!(resp.len(), 24);
        resp.sort_by(|a, b| a.id.cmp(&b.id));

        for (i, r) in resp.iter().enumerate() {
            assert_eq!(r.id, i + 4900);
        }
        unsafe {
            IndexedFileStorer::init(root)
                .unwrap()
                .remove_base()
                .unwrap()
        };
    }

    #[tokio::test]
    async fn unauthorized() {
        let scan: models::Scan = models::Scan::default();
        let ctx = ContextBuilder::new()
            .api_key(Some("mtls_is_preferred".to_string()))
            .scanner(NoOpScanner)
            .build();
        let controller = Arc::new(ctx);
        let resp = post_scan(&scan, Arc::clone(&controller)).await;

        assert_eq!(resp.status(), 201);

        let req = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let cid = Arc::new(RwLock::new(ClientIdentifier::Unknown));
        let resp = entrypoint(req, Arc::clone(&controller), cid).await.unwrap();

        assert_eq!(resp.status(), 401);
        let req = Request::builder()
            .uri("/scans")
            .header("X-API-KEY", "mtls_is_preferred")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let cid = Arc::new(RwLock::new(ClientIdentifier::Unknown));
        let resp = entrypoint(req, Arc::clone(&controller), cid).await.unwrap();
        assert_eq!(resp.status(), 201);
    }
}
