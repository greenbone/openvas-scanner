// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

use std::marker::{Send, Sync};

use config::{Config, Mode, ScannerType};
use controller::{Context, ContextBuilder};
use notus::NotusWrapper;
use scannerlib::models::scanner::{
    ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper, Scanner,
};
use scannerlib::nasl::FSPluginLoader;
use scannerlib::notus::{HashsumProductLoader, Notus};
use scannerlib::openvas::{self, cmd};
use scannerlib::osp;
use scannerlib::scanner::ScannerStackWithStorage;
use scannerlib::storage::infisto::{ChaCha20IndexFileStorer, IndexedFileStorer};
use storage::{FromConfigAndFeeds, Storage};
use tls::tls_config;
use tracing::{info, metadata::LevelFilter, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    config::StorageType,
    crypt::ChaCha20Crypt,
    storage::{file, inmemory, redis, FeedHash},
};
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

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn setup_log(config: &Config) {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse_lossy(format!("{},rustls=info,h2=info", &config.log.level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn get_feeds(config: &Config) -> Vec<FeedHash> {
    match config.mode {
        Mode::Service => vec![
            FeedHash::nasl(&config.feed.path),
            FeedHash::advisories(&config.notus.advisories_path),
        ],
        Mode::ServiceNotus => vec![FeedHash::advisories(&config.notus.advisories_path)],
    }
}

fn check_redis_url(config: &mut Config) -> String {
    let redis_url = cmd::get_redis_socket();
    if redis_url != config.storage.redis.url {
        warn!(openvas_redis=&redis_url, openvasd_redis=&config.storage.redis.url, "openvas and openvasd use different redis connection. Overriding openvasd#storage.redis.url");
        config.storage.redis.url = redis_url.clone();
    }
    redis_url
}

fn make_osp_scanner(config: &Config) -> osp::Scanner {
    if !config.scanner.ospd.socket.exists() && config.mode != Mode::ServiceNotus {
        warn!("OSPD socket {} does not exist. Some commands will not work until the socket is created!", config.scanner.ospd.socket.display());
    }
    osp::Scanner::new(
        config.scanner.ospd.socket.clone(),
        config.scanner.ospd.read_timeout,
    )
}

fn make_openvas_scanner(mut config: Config) -> openvas::Scanner {
    let redis_url = check_redis_url(&mut config);
    openvas::Scanner::new(
        config.scheduler.min_free_mem,
        None,
        cmd::check_sudo(),
        redis_url,
    )
}

fn make_openvasd_scanner<S>(
    config: &Config,
    storage: S,
) -> scannerlib::scanner::Scanner<ScannerStackWithStorage<S>>
where
    S: storage::NaslStorage + Send + 'static,
{
    scannerlib::scanner::Scanner::with_storage(storage, &config.feed.path)
}

async fn create_context<DB, ScanHandler>(
    db: DB,
    sh: ScanHandler,
    config: &Config,
) -> Context<ScanHandler, DB>
where
    ScanHandler:
        ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Sync + Send + 'static,
{
    let mut ctx_builder = ContextBuilder::new();

    let loader = FSPluginLoader::new(config.notus.products_path.to_string_lossy().to_string());
    match HashsumProductLoader::new(loader) {
        Ok(loader) => {
            let notus = Notus::new(loader, config.feed.signature_check);
            ctx_builder = ctx_builder.notus(NotusWrapper::new(notus));
        }
        Err(e) => warn!("Notus Scanner disabled: {e}"),
    }
    tracing::warn!(enable_get_scans = config.endpoints.enable_get_scans);

    ctx_builder
        .mode(config.mode.clone())
        .scheduler_config(config.scheduler.clone())
        .feed_config(config.feed.clone())
        .await
        .scanner(sh)
        .tls_config(tls_config(config).unwrap_or(None))
        .api_key(config.endpoints.key.clone())
        .enable_get_scans(config.endpoints.enable_get_scans)
        .storage(db)
        .build()
}

async fn run_with_scanner_and_storage<Sc, St>(
    scanner: Sc,
    storage: St,
    config: &Config,
) -> Result<()>
where
    St: Storage + Send + Sync + 'static,
    Sc: Scanner + Send + Sync + 'static,
{
    let ctx = create_context(storage, scanner, config).await;
    controller::run(ctx, config).await
}

async fn run_with_storage<St>(config: &Config) -> Result<()>
where
    St: FromConfigAndFeeds + storage::ResultHandler + Storage + Send + 'static + Sync,
{
    let feeds = get_feeds(config);
    let storage = St::from_config_and_feeds(config, feeds)?;

    match config.scanner.scanner_type {
        ScannerType::OSPD => {
            let scanner = make_osp_scanner(config);
            run_with_scanner_and_storage(scanner, storage, config).await
        }
        ScannerType::Openvas => {
            let scanner = make_openvas_scanner(config.clone());
            run_with_scanner_and_storage(scanner, storage, config).await
        }
        ScannerType::Openvasd => {
            let storage = std::sync::Arc::new(storage::UserNASLStorageForKBandVT::new(storage));
            let scanner = make_openvasd_scanner(config, storage.clone());
            run_with_scanner_and_storage(scanner, storage, config).await
        }
    }
}

async fn run(config: &Config) -> Result<()> {
    info!(mode = ?config.mode, storage_type=?config.storage.storage_type, "Configuring storage devices");
    match config.storage.storage_type {
        StorageType::Redis => {
            info!(url = config.storage.redis.url, "Using redis storage.");
            run_with_storage::<redis::Storage<inmemory::Storage<ChaCha20Crypt>>>(config).await
        }
        StorageType::InMemory => {
            info!("Using in-memory storage. No sensitive data will be stored on disk.");
            run_with_storage::<inmemory::Storage<ChaCha20Crypt>>(config).await
        }
        StorageType::FileSystem => {
            if config.storage.fs.key.is_some() {
                info!("Using in-file storage. Sensitive data will be encrypted stored on disk.");
                run_with_storage::<file::Storage<ChaCha20IndexFileStorer<IndexedFileStorer>>>(
                    config,
                )
                .await
            } else {
                warn!(
                    "Using in-file storage. Sensitive data will be stored on disk without any encryption."
                );
                run_with_storage::<file::Storage<IndexedFileStorer>>(config).await
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load();
    tracing::debug!(key = config.storage.fs.key);
    setup_log(&config);
    run(&config).await
}
