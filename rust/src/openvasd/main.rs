// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
// We allow this fow now, since it would require lots of changes
// but should eventually solve this.

mod config;
mod crypt;
mod json_stream;
mod notus;
mod scans;
mod vts;

use sqlx::migrate::Migrator;
use std::{
    marker::{Send, Sync},
    pin::Pin,
    sync::Arc,
};

use config::{Config, StorageType};
use greenbone_scanner_framework::{RuntimeBuilder, ServerCertificate};
use notus::config_to_products;
use scannerlib::{
    container_image_scanner::{
        self,
        config::{DBLocation, SqliteConfiguration},
    },
    models::FeedState,
};
use sqlx::SqlitePool;

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

fn get_feed_state(
    vts: Arc<vts::Endpoints>,
) -> impl Fn() -> Pin<Box<dyn Future<Output = FeedState> + Send + 'static>> {
    move || {
        let vts = vts.clone();
        Box::pin(async move { vts.feed_state().await })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load();
    config.logging.init();

    //TODO: AsRef impl for Config
    let products = config_to_products(&config);
    let pool = setup_sqlite(&config).await?;
    let (feed_state2, vts) = vts::init(pool.clone(), &config).await;
    let vts = Arc::new(vts);
    let scan = scans::init(pool.clone(), &config, get_feed_state(vts.clone())).await?;
    let (get_notus, post_notus) = notus::init(products.clone());

    let mut rb = RuntimeBuilder::<greenbone_scanner_framework::End>::new(config.listener.address)
        // TODO: use a lambda like in scanner instead.
        // That way we don't need to manage tokio::spawn_blocking all over the place
        .feed_version(feed_state2.clone());
    match (config.tls.certs.clone(), config.tls.key.clone()) {
        (Some(certificate), Some(key)) => {
            rb = rb.server_tls_cer(ServerCertificate::new(key, certificate))
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

    let (cis_scans, cis_vts) = container_image_scanner::init(
        pool.clone(),
        feed_state2,
        products,
        config.container_image_scanner,
    )
    .await?;

    rb.insert_scans(Arc::new(scan))
        .insert_get_vts(vts.clone())
        .add_request_handler(get_notus)
        .add_request_handler(post_notus)
        .insert_additional_scan_endpoints(Arc::new(cis_scans), Arc::new(cis_vts))
        .run_blocking()
        .await
}
