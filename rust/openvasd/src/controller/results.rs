// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines the result fetching loop.
//!
//! This loop should be run as background task to fetch results from the scanner.

use models::scanner::Scanner;

use std::sync::Arc;

use super::context::Context;

/// Defines the result fetching loop.
///
/// This loop should be run as background task to fetch results from the scanner.
pub async fn fetch<S, DB>(ctx: Arc<Context<S, DB>>)
where
    S: Scanner + 'static + std::marker::Send + std::marker::Sync,
    DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
{
    let mut interval = tokio::time::interval(ctx.scheduler.config().check_interval);
    tracing::debug!("Starting synchronization loop");
    let mut warn = true;
    loop {
        interval.tick().await;
        if *ctx.abort.read().unwrap() {
            tracing::trace!("aborting");
            break;
        }
        match ctx.scheduler.sync_scans().await {
            Ok(_) => {
                if !warn {
                    tracing::info!("fetch results recovered.");
                    warn = true;
                }
            }
            Err(e) => {
                if warn {
                    warn = false;
                    tracing::warn!(%e, "results sync failed")
                }
            }
        }
    }
}
