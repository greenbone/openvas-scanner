// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

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

use std::sync::Arc;

use anyhow::{Context, Result};
use api::Authentication;
use config::Config;
use database::sqlite;
use scannerlib::utils::version::show_version;

use crate::api::ApiConfig;

/// Initializes all dependencies required to serve the API.
pub async fn init_api(config: Config) -> Result<ApiConfig> {
    let notus = notus::init(&config);
    let pool = sqlite::init(&config).await?;
    let (sender, feed) = vts::init(pool.clone(), &config).await;
    let scanner = scans::init(pool.clone(), &config, sender).await?;
    let image_scanner =
        container_image_scanner::init(notus.clone(), config.container_image_scanner.clone())
            .await?;

    let tls_cfg = config.tls().context("configuration error")?;

    let auth_method = match (
        tls_cfg.client_certs.is_some(),
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
        tls_cfg,
        // TODO: make new variable?
        max_requests: config.storage.max_http_connections(),
        api_keys: Arc::new(config.endpoints.key.map(|x| vec![x]).unwrap_or(vec![])),
        feed,
        scanner,
        image_scanner,
        notus,
        enable_additional_routes: config.endpoints.enable_get_scans,
    })
}

async fn _main() -> Result<i32> {
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
