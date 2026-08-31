// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
// We allow this fow now, since it would require lots of changes
// but should eventually solve this.

mod api;
#[cfg(test)]
mod api_tests;
mod config;
mod container_image_scanner;
mod crypt;
mod database;
mod json_stream;
mod notus;
mod scans;
mod vts;

use sqlx::migrate::Migrator;
use std::sync::Arc;

use api::Authentication;
use config::{Config, StorageType};
use container_image_scanner::config::{DBLocation, SqliteConfiguration};
use notus::config_to_products;
use scannerlib::{models::FeedState, utils::version::show_version};
use sqlx::SqlitePool;

use crate::api::ApiConfig;

static MIGRATOR: Migrator = sqlx::migrate!();

// TODO: move to config
async fn setup_sqlite(config: &Config) -> anyhow::Result<SqlitePool> {
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

/// Initializes all dependencies required to serve the API.
pub async fn init_api(config: Config) -> anyhow::Result<ApiConfig> {
    let products = config_to_products(&config);
    let pool = setup_sqlite(&config).await?;
    let feed_state = Arc::new(std::sync::RwLock::new(FeedState::Unknown));
    let (sender, feed) = vts::init(pool.clone(), &config, feed_state.clone()).await;
    let scanner = scans::init(pool.clone(), &config, sender).await?;
    let image_scanner =
        container_image_scanner::init(products.clone(), config.container_image_scanner).await?;

    let auth_method = match (
        config.tls.client_certs.is_some() && config.tls.certs.is_some() && config.tls.key.is_some(),
        config.endpoints.key.is_some(),
    ) {
        (true, true) => {
            tracing::info!("mTLS and api-key configured, favoring mTLS and disabling api-key");
            Authentication::Mtls
        }
        (true, false) => Authentication::Mtls,
        (false, true) => Authentication::ApiKey,
        (false, false) => {
            tracing::warn!("neither api-key nor mTLS configured. Endpoints are not secured.");
            Authentication::Disabled
        }
    };

    if !config.feed.signature_check {
        tracing::warn!(
            "Integrity check for feed has been disabled. Neither hashsums nor GPG signature will get verified."
        )
    }

    Ok(ApiConfig {
        address: config.listener.address,
        auth_method,
        server_cert_path: config.tls.certs,
        server_key_file: config.tls.key,
        client_certs_path: config.tls.client_certs,
        // TODO: make new variable?
        max_requests: config.storage.max_http_connections(),
        api_keys: Arc::new(config.endpoints.key.map(|x| vec![x]).unwrap_or(vec![])),
        feed,
        scanner,
        image_scanner,
        notus: products,
        enable_additional_routes: config.endpoints.enable_get_scans,
    })
}

async fn _main() -> anyhow::Result<i32> {
    let config = Config::load();
    let _guard = config.logging.init();

    show_version("openvasd");
    if config.version {
        return Ok(0);
    }

    let cfg = init_api(config).await?;
    api::run(&cfg).await
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
