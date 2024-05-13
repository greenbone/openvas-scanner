// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use ::notus::{loader::hashsum::HashsumProductLoader, notus::Notus};
use models::scanner::{ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper};
use nasl_interpreter::FSPluginLoader;
use notus::NotusWrapper;

use crate::storage::FeedHash;
pub mod config;
pub mod controller;
pub mod crypt;
pub mod feed;
pub mod notus;
pub mod preference;
pub mod request;
pub mod response;
mod scheduling;
pub mod storage;
pub mod tls;

fn create_context<DB, ScanHandler>(
    db: DB,
    sh: ScanHandler,
    config: &config::Config,
) -> controller::Context<ScanHandler, DB>
where
    ScanHandler: ScanStarter
        + ScanStopper
        + ScanDeleter
        + ScanResultFetcher
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static,
{
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
        .mode(config.mode.clone())
        .scheduler_config(config.scheduler.clone())
        .feed_config(config.feed.clone())
        .scanner(sh)
        .api_key(config.endpoints.key.clone())
        .enable_get_scans(config.endpoints.enable_get_scans)
        .storage(db)
        .build()
}

async fn run<S>(
    scanner: S,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: ScanStarter
        + ScanStopper
        + ScanDeleter
        + ScanResultFetcher
        + std::fmt::Debug
        + std::marker::Sync
        + std::marker::Send
        + 'static,
{
    tracing::info!(mode = ?config.mode, storage_type=?config.storage.storage_type, "configuring storage devices");
    let feeds = match config.mode {
        config::Mode::Service => vec![
            FeedHash::nasl(&config.feed.path),
            FeedHash::advisories(&config.notus.advisories_path),
        ],

        config::Mode::ServiceNotus => vec![FeedHash::advisories(&config.notus.advisories_path)],
    };
    match config.storage.storage_type {
        config::StorageType::Redis => {
            tracing::info!(url = config.storage.redis.url, "using redis");

            let ic = storage::inmemory::Storage::new(
                crate::crypt::ChaCha20Crypt::default(),
                feeds.clone(),
            );
            let ctx = create_context(
                storage::redis::Storage::new(ic, config.storage.redis.url.clone(), feeds),
                scanner,
                config,
            );
            controller::run(ctx, config).await
        }
        config::StorageType::InMemory => {
            tracing::info!("using in memory store. No sensitive data will be stored on disk.");
            // Self::new(crate::crypt::ChaCha20Crypt::default(), "/var/lib/openvas/feed".to_string())
            let ctx = create_context(
                storage::inmemory::Storage::new(crate::crypt::ChaCha20Crypt::default(), feeds),
                scanner,
                config,
            );
            controller::run(ctx, config).await
        }
        config::StorageType::FileSystem => {
            if let Some(key) = &config.storage.fs.key {
                tracing::info!(
                    "using in file storage. Sensitive data will be encrypted stored on disk."
                );

                let ctx = create_context(
                    storage::file::encrypted(&config.storage.fs.path, key, feeds)?,
                    scanner,
                    config,
                );
                controller::run(ctx, config).await
            } else {
                tracing::warn!(
                    "using in file storage. Sensitive data will be stored on disk without any encryption."
                );
                let ctx = create_context(
                    storage::file::unencrypted(&config.storage.fs.path, feeds)?,
                    scanner,
                    config,
                );
                controller::run(ctx, config).await
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut config = config::Config::load();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .parse_lossy(format!("{},rustls=info,h2=info", &config.log.level));
    tracing::debug!("config: {:?}", config);
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if !config.scanner.ospd.socket.exists() {
        tracing::warn!("OSPD socket {} does not exist. Some commands will not work until the socket is created!", config.scanner.ospd.socket.display());
    }
    match config.scanner.scanner_type {
        config::ScannerType::OSPD => {
            run(
                osp::Scanner::new(
                    config.scanner.ospd.socket.clone(),
                    config.scanner.ospd.read_timeout,
                ),
                &config,
            )
            .await
        }
        config::ScannerType::Openvas => {
            let redis_url = openvas::cmd::get_redis_socket();
            if redis_url != config.storage.redis.url {
                tracing::warn!(openvas_redis=&redis_url, openvasd_redis=&config.storage.redis.url, "openvas and openvasd use different redis connection. Overriding openvasd#storage.redis.url");
                config.storage.redis.url.clone_from(&redis_url);
            }
            run(
                openvas::Scanner::new(
                    config.scheduler.min_free_mem,
                    None,
                    openvas::cmd::check_sudo(),
                    redis_url,
                ),
                &config,
            )
            .await
        }
    }
}
