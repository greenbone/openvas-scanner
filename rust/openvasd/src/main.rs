// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use ::notus::{loader::hashsum::HashsumProductLoader, notus::Notus};
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

    let loader = FSPluginLoader::new(config.notus.products_path.to_string_lossy().to_string());
    match HashsumProductLoader::new(loader) {
        Ok(loader) => {
            let notus = Notus::new(loader, config.feed.signature_check);
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


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config::Config::load();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .parse_lossy(format!("{},rustls=info", &config.log.level));
    tracing::debug!("config: {:?}", config);
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if !config.ospd.socket.exists() {
        tracing::warn!("OSPD socket {} does not exist. Some commands will not work until the socket is created!", config.ospd.socket.display());
    }
    match config.storage.storage_type {
        config::StorageType::InMemory => {
            tracing::info!("using in memory store. No sensitive data will be stored on disk.");

            let ctx = create_context(storage::inmemory::Storage::default(), &config);
            controller::run(ctx, &config).await
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
                controller::run(ctx, &config).await
            } else {
                tracing::warn!(
                    "using in file storage. Sensitive data will be stored on disk without any encryption."
                );
                let ctx = create_context(
                    storage::file::unencrypted(&config.storage.fs.path)?,
                    &config,
                );
                controller::run(ctx, &config).await
            }
        }
    }
}
