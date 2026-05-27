// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
// We allow this fow now, since it would require lots of changes
// but should eventually solve this.

mod app;
mod config;
mod container_image_scanner;
mod credentials;
mod crypt;
mod database;
mod framework;
mod json_stream;
mod notus;
mod scan_routes;
mod scans;
mod scheduler_common;
mod server;
mod vts;

use sqlx::migrate::Migrator;
use std::{
    marker::{Send, Sync},
    sync::Arc,
};

use config::{Config, StorageType};
use container_image_scanner::config::{DBLocation, SqliteConfiguration};
use notus::config_to_products;
use scannerlib::models::FeedState;
use scannerlib::utils::version::show_version;
use sqlx::SqlitePool;

use crate::app::AppState;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

static MIGRATOR: Migrator = sqlx::migrate!();

// TODO: move to config
async fn setup_sqlite(config: &Config) -> Result<SqlitePool> {
    let result = match config.storage.clone() {
        config::StorageTypes::V1(storage_v1) => {
            let mut sqliteconfig = SqliteConfiguration::default();

            match storage_v1.storage_type {
                StorageType::InMemory | StorageType::Redis => {}
                StorageType::FileSystem if storage_v1.fs.path.is_dir() => {
                    let mut p = storage_v1.fs.path.clone();
                    p.push("openvasd.db");
                    sqliteconfig.location = DBLocation::File(p);
                }
                StorageType::FileSystem => {
                    sqliteconfig.location = DBLocation::File(storage_v1.fs.path);
                }
            };
            sqliteconfig
        }
        config::StorageTypes::V2(sqlite_configuration) => sqlite_configuration,
    }
    .create_pool("openvasd")
    .await?;
    MIGRATOR.run(&result).await?;
    Ok(result)
}

async fn _main() -> Result<i32> {
    let config = Config::load();
    let _guard = config.logging.init();

    show_version("openvasd");
    if config.version {
        return Ok(0);
    }

    let products = config_to_products(&config);
    let pool = setup_sqlite(&config).await?;
    let feed_snapshot = Arc::new(std::sync::RwLock::new(FeedState::Unknown));
    let sender = vts::init(pool.clone(), &config, feed_snapshot.clone()).await;

    let scan = scans::init(pool.clone(), &config, sender).await?;

    match (config.tls.certs.clone(), config.tls.key.clone()) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            tracing::warn!(
                "Invalid TLS configuration. Please provide a certificate path and a key path. Falling back to http."
            )
        }
    };
    if !config.feed.signature_check {
        tracing::warn!(
            "Integrity check for feed has been disabled. Neither hashsums nor GPG signature will get verified."
        );
    }
    let cis_scan_state =
        container_image_scanner::init(products.clone(), config.container_image_scanner.clone())
            .await?;

    let scan_state = Arc::new(scan);
    let cis_scan_state = Arc::new(cis_scan_state);
    let app_state = AppState {
        feed_state: feed_snapshot,
        config: &config,
        scan_state,
        cis_scan_state,
        notus_state: products,
    };

    server::serve(&app_state).await
}

#[tokio::main]
async fn main() {
    let rc = match _main().await {
        Ok(x) => x,
        Err(error) => {
            panic!("{error}")
        }
    };
    // we call process exit, on return ExitCode it kept lingering.
    // when a task is blocking.
    std::process::exit(rc);
}
