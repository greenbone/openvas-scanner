// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use ::notus::{loader::hashsum::HashsumAdvisoryLoader, notus::Notus};
use controller::ClientGossiper;
use futures_util::ready;
use nasl_interpreter::FSPluginLoader;
use notus::NotusWrapper;

pub mod config;
pub mod controller;
pub mod crypt;
pub mod feed;
pub mod notus;
pub mod request;
pub mod response;
pub mod scan;
pub mod storage;
pub mod tls;

struct AddrIncomingWrapper(hyper::server::conn::AddrIncoming);

impl hyper::server::accept::Accept for AddrIncomingWrapper {
    type Conn = AddrStreamWrapper;
    type Error = std::io::Error;

    fn poll_accept(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Self::Conn, Self::Error>>> {
        use core::task::Poll;
        use std::pin::Pin;
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.0).poll_accept(cx)) {
            Some(Ok(sock)) => std::task::Poll::Ready(Some(Ok(AddrStreamWrapper::new(sock)))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}
struct AddrStreamWrapper(
    hyper::server::conn::AddrStream,
    std::sync::Arc<std::sync::RwLock<controller::ClientIdentifier>>,
);
impl AddrStreamWrapper {
    fn new(sock: hyper::server::conn::AddrStream) -> AddrStreamWrapper {
        AddrStreamWrapper(
            sock,
            std::sync::Arc::new(std::sync::RwLock::new(
                controller::ClientIdentifier::Unknown,
            )),
        )
    }
}

impl ClientGossiper for AddrStreamWrapper {
    fn client_identifier(
        &self,
    ) -> &std::sync::Arc<std::sync::RwLock<controller::ClientIdentifier>> {
        &self.1
    }
}

impl tokio::io::AsyncRead for AddrStreamWrapper {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        std::pin::Pin::new(&mut pin.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AddrStreamWrapper {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let pin = self.get_mut();
        std::pin::Pin::new(&mut pin.0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let pin = self.get_mut();
        std::pin::Pin::new(&mut pin.0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let pin = self.get_mut();
        std::pin::Pin::new(&mut pin.0).poll_shutdown(cx)
    }
}

fn create_context<DB>(
    db: DB,
    config: &config::Config,
) -> controller::Context<scan::OSPDWrapper, DB> {
    let scanner = scan::OSPDWrapper::new(config.ospd.socket.clone(), config.ospd.read_timeout);
    let rc = config.ospd.result_check_interval;
    let fc = (
        config.feed.path.clone(),
        config.feed.check_interval,
        config.feed.signature_check,
    );
    let mut ctx_builder = controller::ContextBuilder::new();

    let loader = FSPluginLoader::new(config.notus.advisory_path.to_string_lossy().to_string());
    match HashsumAdvisoryLoader::new(loader) {
        Ok(loader) => {
            let notus = Notus::new(loader);
            ctx_builder = ctx_builder.notus(NotusWrapper::new(notus));
        }
        Err(e) => tracing::warn!("Notus Scanner disabled: {e}"),
    }

    ctx_builder
        .result_config(rc)
        .feed_config(fc)
        .scanner(scanner)
        .api_key(config.endpoints.key.clone())
        .enable_get_scans(config.endpoints.enable_get_scans)
        .storage(db)
        .build()
}

async fn serve<'a, S, DB, I>(
    ctx: controller::Context<S, DB>,
    inc: I,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: scan::ScanStarter
        + scan::ScanStopper
        + scan::ScanDeleter
        + scan::ScanResultFetcher
        + std::marker::Send
        + std::marker::Sync
        + 'static,
    I: hyper::server::accept::Accept,
    I::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    I::Conn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + ClientGossiper + 'static,
    DB: crate::storage::Storage + std::marker::Send + 'static + std::marker::Sync,
{
    let controller = std::sync::Arc::new(ctx);
    let make_svc = {
        use std::sync::Arc;

        tokio::spawn(crate::controller::results::fetch(Arc::clone(&controller)));
        tokio::spawn(crate::controller::feed::fetch(Arc::clone(&controller)));

        use hyper::service::{make_service_fn, service_fn};
        make_service_fn(|conn| {
            let controller = Arc::clone(&controller);
            let conn = conn as &dyn ClientGossiper;
            let cis = Arc::clone(conn.client_identifier());
            async {
                Ok::<_, crate::scan::Error>(service_fn(move |req| {
                    controller::entrypoint(req, Arc::clone(&controller), cis.clone())
                }))
            }
        })
    };
    let server = hyper::Server::builder(inc).serve(make_svc);
    server.await?;
    Ok(())
}

pub async fn run<'a, S, DB>(
    mut ctx: controller::Context<S, DB>,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: scan::ScanStarter
        + scan::ScanStopper
        + scan::ScanDeleter
        + scan::ScanResultFetcher
        + std::marker::Send
        + std::marker::Sync
        + 'static,
    DB: crate::storage::Storage + std::marker::Send + 'static + std::marker::Sync,
{
    let addr = config.listener.address;
    let incoming = hyper::server::conn::AddrIncoming::bind(&addr)?;
    let addr = incoming.local_addr();
    if let Some((roots, certs, key)) = tls::tls_config(config)? {
        tracing::info!("listening on https://{}", addr);
        if !roots.is_empty() && ctx.api_key.is_some() {
            tracing::warn!("Client certificates and api key are configured. To disable the possibility to bypass client verification the API key is ignored.");
            ctx.api_key = None;
        }
        let inc = tls::TlsAcceptor::new(roots, certs, key, incoming);
        serve(ctx, inc).await?;
    } else {
        tracing::info!("listening on http://{}", addr);
        serve(ctx, AddrIncomingWrapper(incoming)).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config::Config::load();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .parse_lossy(format!("info,openvasd={}", &config.log.level));
    tracing::debug!("config: {:?}", config);
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if !config.ospd.socket.exists() {
        tracing::warn!("OSPD socket {} does not exist. Some commands will not work until the socket is created!", config.ospd.socket.display());
    }
    match config.storage.storage_type {
        config::StorageType::InMemory => {
            tracing::info!("using in memory store. No sensitive data will be stored on disk.");

            let ctx = create_context(storage::inmemory::Storage::default(), &config);
            run(ctx, &config).await
        }
        config::StorageType::FileSystem => {
            if let Some(key) = &config.storage.fs.key {
                tracing::info!(
                    "using in file storage. Sensitive data will be encrypted stored on disk."
                );

                let ctx = create_context(
                    storage::file::encrypted(&config.storage.fs.path, key)?,
                    &config,
                );
                run(ctx, &config).await
            } else {
                tracing::warn!(
                    "using in file storage. Sensitive data will be stored on disk without any encryption."
                );
                let ctx = create_context(
                    storage::file::unencrypted(&config.storage.fs.path)?,
                    &config,
                );
                run(ctx, &config).await
            }
        }
    }
}
