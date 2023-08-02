// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod config;
mod controller;
mod crypt;
mod feed;
mod request;
mod response;
mod scan;
mod storage;
mod tls;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config::Config::load();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .parse_lossy(config.log.level.clone());
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let rc = config.ospd.result_check_interval;
    let fc = (config.feed.path.clone(), config.feed.check_interval);
    if !config.ospd.socket.exists() {
        tracing::warn!("OSPD socket {} does not exist. Some commands will not work until the socket is created!", config.ospd.socket.display());
    }
    let scanner = scan::OSPDWrapper::new(config.ospd.socket.clone());
    let ctx = controller::ContextBuilder::new()
        .result_config(rc)
        .feed_config(fc)
        .scanner(scanner)
        .api_key(config.endpoints.key.clone())
        .enable_get_scans(config.endpoints.enable_get_scans)
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
