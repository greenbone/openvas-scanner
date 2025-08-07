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

use config::Config;
use greenbone_scanner_framework::RuntimeBuilder;
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
pub async fn setup_sqlite(config: &Config, shared: bool) -> Result<SqlitePool> {
    use sqlx::{
        Sqlite,
        pool::PoolOptions,
        sqlite::{SqliteConnectOptions, SqliteJournalMode},
    };
    use std::time::Duration;
    fn from_config_to_sqlite_address(config: &Config, shared: bool) -> String {
        use crate::config::StorageType;

        match config.storage.storage_type {
            StorageType::InMemory if shared => "sqlite::memory:?cache=shared".to_owned(),
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

    let options = SqliteConnectOptions::from_str(&from_config_to_sqlite_address(config, shared))?
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

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load();
    setup_log(&config);
    let pool = setup_sqlite(&config, true).await?;
    let scan = scans::init(pool.clone(), &config);
    let vts = vts::init(pool, &config).await;
    let (get_notus, post_notus) = notus::init(&config);

    RuntimeBuilder::<greenbone_scanner_framework::End>::new()
        //TODO: feed version needs to be getable
        .feed_version("bla".to_owned())
        .insert_scans(Arc::new(scan))
        .insert_get_vts(Arc::new(vts))
        .insert_on_request(get_notus)
        .insert_on_request(post_notus)
        .run_blocking()
        .await
}
