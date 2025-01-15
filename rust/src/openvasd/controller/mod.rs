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

use crate::config;
pub use context::{Context, ContextBuilder, NoOpScanner};
use hyper_util::rt::{TokioExecutor, TokioIo};
use scannerlib::models;
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

pub async fn run<S, DB>(
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
    let addr = config.listener.address;
    let addr: SocketAddr = addr;
    let incoming = TcpListener::bind(&addr).await?;

    let tls_config = ctx.tls_config.take();
    let controller = std::sync::Arc::new(ctx);
    tracing::info!(?config.mode, "running in");
    if config.mode == config::Mode::Service {
        tokio::spawn(crate::controller::results::fetch(Arc::clone(&controller)));
    }
    tokio::spawn(crate::controller::feed::fetch(Arc::clone(&controller)));

    if let Some(tls_config) = tls_config {
        use hyper::server::conn::http2::Builder;
        tracing::info!("listening on https://{}", addr);

        let config = Arc::new(tls_config.config);
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(config);

        loop {
            let (tcp_stream, _remote_addr) = incoming.accept().await?;

            let tls_acceptor = tls_acceptor.clone();
            let identifier = tls_config.client_identifier.clone();
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
    use scannerlib::models::Scan;

    use crate::controller::ClientIdentifier;

    #[tokio::test]
    async fn contains_version() {
        let client = super::entry::client::in_memory_example_feed().await;
        let header = client.header().await.unwrap();
        assert_eq!(header.get("api-version").unwrap(), "1");
        assert_eq!(header.get("authentication").unwrap(), "x-api-key");
    }

    #[tokio::test]
    async fn get_scan_preferences() {
        let client = super::entry::client::in_memory_example_feed().await;
        let result = client.scans_preferences().await.unwrap();
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn unauthorized() {
        let mut client = super::entry::client::in_memory_example_feed().await;
        let scan: Scan = Scan::default();
        let id = client.scan_create(&scan).await.unwrap();
        let _ = client.scan(&id).await.unwrap();
        client.set_client(ClientIdentifier::Known("holla".into()));
        assert!(
            client.scan(&id).await.is_err(),
            "expected to not be allowed to get that scan with another cid"
        );
        client.set_client(ClientIdentifier::Unknown);
        assert!(
            client.scan(&id).await.is_err(),
            "expected to not be allowed to get that scan without cid"
        );
    }
}
