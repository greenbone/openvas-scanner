// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod context;
pub mod entry;
pub mod feed;
pub mod results;

use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use crate::{
    config,
    tls::{self},
};
pub use context::{Context, ContextBuilder, NoOpScanner};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

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
#[derive(Default, Debug, Clone)]
pub enum ClientIdentifier {
    /// When there in no information available
    #[default]
    Unknown,
    /// Purposely disabled
    Disabled,
    /// Contains a hashed number of an identifier
    ///
    /// openvasd uses the identifier as a key for results. This key is usually calculated by an
    /// subject of a known client certificate. Based on that we don't need more information.
    Known(ClientHash),
}

fn retrieve_and_reset(id: Arc<RwLock<ClientIdentifier>>) -> ClientIdentifier {
    // get client information
    let mut ci = id.write().unwrap();
    let cci = ci.clone();
    // reset client information
    *ci = ClientIdentifier::Unknown;
    cci
}
pub async fn run<'a, S, DB>(
    mut ctx: Context<S, DB>,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: models::scanner::ScanStarter
        + models::scanner::ScanStopper
        + models::scanner::ScanDeleter
        + models::scanner::ScanResultFetcher
        + std::marker::Send
        + std::marker::Sync
        + 'static,
    DB: crate::storage::Storage + std::marker::Send + 'static + std::marker::Sync,
{
    let tlsc = {
        if let Some((c, conf, has_clients)) = tls::tls_config(config)? {
            if has_clients && ctx.api_key.is_some() {
                tracing::warn!("Client certificates and api key are configured. To disable the possibility to bypass client verification the API key is ignored.");
                ctx.api_key = None;
            }
            Some((c, conf))
        } else {
            None
        }
    };
    if tlsc.is_none() && ctx.api_key.is_none() {
        tracing::warn!("Neither mTLS nor an API key are set. /scans endpoint is unsecured.");
    }
    let addr = config.listener.address;
    let addr: SocketAddr = addr;
    let incoming = TcpListener::bind(&addr).await?;

    let controller = std::sync::Arc::new(ctx);
    tracing::info!(?config.mode, "running in");
    if config.mode == config::Mode::Service {
        tokio::spawn(crate::controller::results::fetch(Arc::clone(&controller)));
    }
    tokio::spawn(crate::controller::feed::fetch(Arc::clone(&controller)));

    if let Some((ci, conf)) = tlsc {
        use hyper::server::conn::http2::Builder;
        tracing::info!("listening on https://{}", addr);

        let config = Arc::new(conf);
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(config);

        loop {
            let (tcp_stream, _remote_addr) = incoming.accept().await?;

            let tls_acceptor = tls_acceptor.clone();
            let identifier = ci.clone();
            let ctx = controller.clone();
            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(err) => {
                        tracing::debug!("failed to perform tls handshake: {err:#}");
                        return;
                    }
                };
                let cci = retrieve_and_reset(identifier);
                let service = entry::EntryPoint::new(ctx, Arc::new(cci));
                if let Err(err) = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await
                {
                    tracing::debug!("failed to serve connection: {err:#}");
                }
            });
        }
    } else {
        use hyper::server::conn::http1::Builder;
        tracing::info!("listening on http://{}", addr);
        loop {
            let (tcp_stream, _remote_addr) = incoming.accept().await?;
            let ctx = controller.clone();
            tokio::spawn(async move {
                let cci = ClientIdentifier::Disabled;
                let service = entry::EntryPoint::new(ctx, Arc::new(cci));
                if let Err(err) = Builder::new()
                    .serve_connection(TokioIo::new(tcp_stream), service)
                    .await
                {
                    tracing::debug!("failed to serve connection: {err:#}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::context::Context;
    use crate::{
        controller::{ClientIdentifier, ContextBuilder, NoOpScanner},
        storage::{file, FeedHash},
    };
    use async_trait::async_trait;
    use hyper::{body::Bytes, service::HttpService, Method, Request, Version};
    use infisto::base::IndexedFileStorer;
    use models::scanner::{
        ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper, Scanner,
    };
    use std::sync::{Arc, RwLock};

    #[derive(Debug, Clone)]
    struct FakeScanner {
        count: Arc<RwLock<usize>>,
    }

    #[async_trait]
    impl models::scanner::ScanStarter for FakeScanner {
        async fn start_scan(&self, _scan: models::Scan) -> Result<(), models::scanner::Error> {
            Ok(())
        }

        async fn can_start_scan(&self, _: &models::Scan) -> bool {
            true
        }
    }

    #[async_trait]
    impl models::scanner::ScanStopper for FakeScanner {
        async fn stop_scan<I>(&self, _id: I) -> Result<(), models::scanner::Error>
        where
            I: AsRef<str> + Send,
        {
            Ok(())
        }
    }

    #[async_trait]
    impl models::scanner::ScanDeleter for FakeScanner {
        async fn delete_scan<I>(&self, _id: I) -> Result<(), models::scanner::Error>
        where
            I: AsRef<str> + Send,
        {
            Ok(())
        }
    }

    #[async_trait]
    impl models::scanner::ScanResultFetcher for FakeScanner {
        async fn fetch_results<I>(
            &self,
            id: I,
        ) -> Result<models::scanner::ScanResults, models::scanner::Error>
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
                    Ok(ScanResults {
                        id: id.as_ref().to_string(),
                        status,
                        results: vec![],
                    })
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
                    Ok(ScanResults {
                        id: id.as_ref().to_string(),
                        status,
                        results,
                    })
                }
                _ => {
                    *count += 1;
                    let status = models::Status {
                        status: models::Phase::Succeeded,
                        ..Default::default()
                    };
                    Ok(ScanResults {
                        id: id.as_ref().to_string(),
                        status,
                        results: vec![],
                    })
                }
            }
        }
    }

    async fn entrypoint<S, DB, R>(
        req: Request<R>,
        ctx: Arc<Context<S, DB>>,
        cid: Arc<ClientIdentifier>,
    ) -> Result<crate::response::Result, models::scanner::Error>
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
        let mut entry = crate::controller::entry::EntryPoint::new(ctx, cid);
        entry.call(req).await
    }
    use http_body_util::{BodyExt, Empty, Full};

    #[tokio::test]
    async fn contains_version() {
        let controller = Arc::new(Context::default());
        let req = Request::builder()
            .method(Method::HEAD)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Unknown);
        let resp = entrypoint(req, Arc::clone(&controller), cid).await.unwrap();
        assert_eq!(resp.headers().get("api-version").unwrap(), "1");
        assert_eq!(resp.headers().get("authentication").unwrap(), "");
    }

    #[tokio::test]
    async fn get_scan_preferences() {
        let controller = Arc::new(Context::default());
        let req = Request::builder()
            .uri("/scans/preferences")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Known("42".into()));
        entrypoint(req, Arc::clone(&controller), cid)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }

    async fn get_scan_status<S, DB>(id: &str, ctx: Arc<Context<S, DB>>) -> crate::response::Result
    where
        S: Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let req = Request::builder()
            .uri(format!("/scans/{id}/status", id = id))
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let cid = Arc::new(ClientIdentifier::Known("42".into()));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn get_scan<S, DB>(id: &str, ctx: Arc<Context<S, DB>>) -> crate::response::Result
    where
        S: Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let req = Request::builder()
            .uri(format!("/scans/{id}", id = id))
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Known("42".into()));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn post_scan<S, DB>(
        scan: &models::Scan,
        ctx: Arc<Context<S, DB>>,
    ) -> crate::response::Result
    where
        S: Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let req: Request<Full<Bytes>> = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(Full::from(serde_json::to_string(&scan).unwrap()))
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Known("42".into()));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn start_scan<S, DB>(id: &str, ctx: Arc<Context<S, DB>>) -> crate::response::Result
    where
        S: Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let action = &models::ScanAction {
            action: models::Action::Start,
        };
        let req: Request<Full<Bytes>> = Request::builder()
            .uri(format!("/scans/{id}", id = id))
            .method(Method::POST)
            .body(serde_json::to_string(action).unwrap().into())
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Known("42".into()));
        entrypoint(req, Arc::clone(&ctx), cid).await.unwrap()
    }

    async fn post_scan_id<S, DB>(scan: &models::Scan, ctx: Arc<Context<S, DB>>) -> String
    where
        S: Scanner + 'static + std::marker::Send + std::marker::Sync,
        DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
    {
        let resp = post_scan(scan, Arc::clone(&ctx)).await;
        let resp = resp.into_body().collect().await.unwrap().to_bytes();
        let resp = String::from_utf8(resp.to_vec()).unwrap();
        let id = resp.trim_matches('"');
        id.to_string()
    }

    #[tokio::test]
    async fn add_scan_with_id_fails() {
        let scan: models::Scan = models::Scan {
            scan_id: "test".to_string(),
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
            .body(Empty::<Bytes>::new())
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Known("42".into()));

        entrypoint(req, Arc::clone(&controller), cid).await.unwrap();
        let resp = get_scan(&id, Arc::clone(&controller)).await;
        assert_eq!(resp.status(), 404);
    }

    use tracing_test::traced_test;
    #[tokio::test]
    #[traced_test]
    async fn fetch_results() {
        async fn get_results<S, DB>(
            id: &str,
            ctx: Arc<Context<S, DB>>,
            idx: Option<usize>,
            range: Option<(usize, usize)>,
        ) -> Vec<models::Result>
        where
            S: Scanner + 'static + std::marker::Send + std::marker::Sync,
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
                .version(Version::HTTP_2)
                .uri(uri)
                .method(Method::GET)
                .body(Empty::<Bytes>::new())
                .unwrap();
            let cid = Arc::new(ClientIdentifier::Known("42".into()));
            let resp = entrypoint(req, Arc::clone(&ctx), cid).await.unwrap();
            let resp = resp.into_body().collect().await.unwrap().to_bytes();

            serde_json::from_slice::<Vec<models::Result>>(&resp).unwrap()
        }

        let scan: models::Scan = models::Scan::default();
        let scanner = FakeScanner {
            count: Arc::new(RwLock::new(0)),
        };
        let ns = crate::config::Scheduler {
            check_interval: std::time::Duration::from_nanos(10),
            ..Default::default()
        };
        let root = "/tmp/openvasd/fetch_results";
        let nfp = "../../examples/feed/nasl";
        let nofp = "../../examples/feed/notus/advisories";
        let storage =
            file::unencrypted(root, vec![FeedHash::nasl(nfp), FeedHash::advisories(nofp)]).unwrap();
        let ctx = ContextBuilder::new()
            .scheduler_config(ns)
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

            let resp = resp.into_body().collect().await.unwrap().to_bytes();
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

        let req: Request<Full<Bytes>> = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Disabled);
        let resp = entrypoint(req, Arc::clone(&controller), cid).await.unwrap();

        assert_eq!(resp.status(), 401);
        let req: Request<Full<Bytes>> = Request::builder()
            .uri("/scans")
            .header("X-API-KEY", "mtls_is_preferred")
            .method(Method::POST)
            .body(serde_json::to_string(&scan).unwrap().into())
            .unwrap();
        let cid = Arc::new(ClientIdentifier::Disabled);
        let resp = entrypoint(req, Arc::clone(&controller), cid).await.unwrap();
        assert_eq!(resp.status(), 201);
    }
}
