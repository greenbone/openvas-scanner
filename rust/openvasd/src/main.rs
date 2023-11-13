// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod config;
mod controller;
mod crypt;
mod feed;
mod notus;
mod request;
mod response;
mod scan;
mod storage;
mod tls;

pub async fn run<'a, DB>(
    db: DB,
    config: config::Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    DB: crate::storage::Storage + std::marker::Send + 'static + std::marker::Sync,
{
    let scanner = scan::OSPDWrapper::new(config.ospd.socket.clone(), config.ospd.read_timeout);
    let rc = config.ospd.result_check_interval;
    let fc = (
        config.feed.path.clone(),
        config.feed.check_interval,
        config.feed.signature_check,
    );
    let ctx_builder = controller::ContextBuilder::new();

    // TODO: Configure Notus for Context

    let ctx = ctx_builder
        .result_config(rc)
        .feed_config(fc)
        .scanner(scanner)
        .api_key(config.endpoints.key.clone())
        .enable_get_scans(config.endpoints.enable_get_scans)
        .storage(db)
        .build();
    let controller = std::sync::Arc::new(ctx);
    let addr = config.listener.address;
    let incoming = hyper::server::conn::AddrIncoming::bind(&addr)?;
    let addr = incoming.local_addr();

    if let Some(tlsc) = tls::tls_config(&config)? {
        tracing::trace!("TLS enabled");
        let make_svc = crate::controller::make_svc!(&controller);
        let server = hyper::Server::builder(tls::TlsAcceptor::new(tlsc, incoming)).serve(make_svc);
        tracing::info!("listening on https://{}", addr);
        server.await?;
    } else {
        let make_svc = crate::controller::make_svc!(&controller);
        let server = hyper::Server::builder(incoming).serve(make_svc);
        tracing::info!("listening on http://{}", addr);
        server.await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config::Config::load();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .parse_lossy(config.log.level.clone());
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if !config.ospd.socket.exists() {
        tracing::warn!("OSPD socket {} does not exist. Some commands will not work until the socket is created!", config.ospd.socket.display());
    }
    match config.storage.storage_type {
        config::StorageType::InMemory => {
            tracing::info!("using in memory store. No sensitive data will be stored on disk.");
            run(storage::inmemory::Storage::default(), config).await
        }
        config::StorageType::FileSystem => {
            if let Some(key) = &config.storage.fs.key {
                tracing::info!(
                    "using in file storage. Sensitive data will be encrypted stored on disk."
                );
                run(
                    storage::file::encrypted(&config.storage.fs.path, key)?,
                    config,
                )
                .await
            } else {
                tracing::warn!(
                    "using in file storage. Sensitive data will be stored on disk without any encryption."
                );
                run(storage::file::unencrypted(&config.storage.fs.path)?, config).await
            }
        }
    }
}
