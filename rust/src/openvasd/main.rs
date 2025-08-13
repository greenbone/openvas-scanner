// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
// We allow this fow now, since it would require lots of changes
// but should eventually solve this.

pub mod config;
pub mod crypt;
mod json_stream;
mod notus;
mod scans;
mod vts;

use std::{
    marker::{Send, Sync},
    str::FromStr,
    sync::Arc,
};

use config::{Config, Endpoints};
use greenbone_scanner_framework::{RuntimeBuilder, ServerCertificate};
use notus::config_to_products;
use scannerlib::{container_image_scanner, models::FeedState};
use sqlx::{SqlitePool, sqlite::SqliteSynchronous};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// TODO: should be on config
fn setup_log(config: &Config) {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse_lossy(format!("{},rustls=info,h2=info", &config.log.level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

// TODO: move to config
pub async fn setup_sqlite(config: &Config) -> Result<SqlitePool> {
    use sqlx::{
        Sqlite,
        pool::PoolOptions,
        sqlite::{SqliteConnectOptions, SqliteJournalMode},
    };
    use std::time::Duration;
    fn from_config_to_sqlite_address(config: &Config) -> String {
        use crate::config::StorageType;

        match config.storage.storage_type {
            //StorageType::InMemory if shared => "sqlite::memory:?cache=shared".to_owned(),
            StorageType::InMemory => "sqlite::memory:".to_owned(),
            StorageType::FileSystem if config.storage.fs.path.is_dir() => {
                let mut p = config.storage.fs.path.clone();
                p.push("openvasd.db");
                format!("sqlite:{}", p.to_string_lossy())
            }
            StorageType::FileSystem => {
                format!("sqlite:{}", config.storage.fs.path.to_string_lossy())
            }
            // actually it can when using the openvas scanner mode
            StorageType::Redis => unreachable!(
                "Redis configuration should never call storage::sqlite::Storage::from_config_and_feeds"
            ),
        }
    }

    // TODO: calculate max_connections or change configuration
    let max_connections = 20;
    // TODO: make busy_timeout a configuration option
    let busy_timeout = Duration::from_secs(2);

    let options = SqliteConnectOptions::from_str(&from_config_to_sqlite_address(config))?
        .journal_mode(SqliteJournalMode::Wal)
        // Although this can lead to data loss in the case that the application crashes we usually
        // need to either restart that scan anyway.
        .synchronous(SqliteSynchronous::Off)
        .busy_timeout(busy_timeout)
        .create_if_missing(true);
    let pool = PoolOptions::<Sqlite>::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub fn get_feed_state(
    vts: Arc<vts::Endpoints>,
) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = FeedState> + Send + 'static>> {
    move || {
        let vts = vts.clone();
        Box::pin(async move { vts.feed_state().await })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    //TODO: merge container_image_scanner::Config into that
    //
    // I prefer the way Duration is handled there as well as logging configuration.
    // Maybe we can find a way to support the new style with the old for downwards compatibility
    // reasons. Additionally the storage configuratio6 is now dated and needs to be overhauled.
    let config = Config::load();
    setup_log(&config);

    //TODO: AsRef impl for Config
    let products = config_to_products(&config);
    let pool = setup_sqlite(&config).await?;
    let (feed_state2, vts) = vts::init(pool.clone(), &config).await;
    let vts = Arc::new(vts);
    let scan = scans::init(pool.clone(), &config, get_feed_state(vts.clone())).await?;
    let (get_notus, post_notus) = notus::init(products.clone());
    let (cis_scans, cis_vts) =
        container_image_scanner::init(pool.clone(), feed_state2.clone(), products).await?;
    let mut rb = RuntimeBuilder::<greenbone_scanner_framework::End>::new()
        // TODO: use a lambda like in scanner instead.
        // That way we don't need to manage tokio::spawn_blocking all over the place
        .feed_version(feed_state2);
    match (config.tls.certs.clone(), config.tls.key.clone()) {
        (Some(certificate), Some(key)) => {
            rb = rb.server_tls_cer(ServerCertificate::new(certificate, key))
        }
        (None, None) => {
            // ok no TLS
        }
        _ => {
            tracing::warn!(
                "Invalid TLS configuration. Please provide a certificate path and a key path. Falling back to http."
            )
        }
    };
    if let Some(client_certs) = config.tls.client_certs.clone() {
        rb = rb.path_client_certs(client_certs);
    }

    rb.insert_scans(Arc::new(scan))
        .insert_get_vts(vts.clone())
        .insert_on_request(get_notus)
        .insert_on_request(post_notus)
        .insert_additional_scan_endpoints(Arc::new(cis_scans), Arc::new(cis_vts))
        .run_blocking()
        .await
}
