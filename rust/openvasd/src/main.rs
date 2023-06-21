// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod config;
mod controller;
mod feed;
mod request;
mod response;
mod scan;
mod tls;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .with_env_var("OPENVASD_LOG")
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let config = config::Config::load();
    let rc = config.ospd.result_check_interval;
    let fc = (config.feed.path.clone(), config.feed.check_interval);
    let scanner = scan::OSPDWrapper::from_env();
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
