// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines the result fetching loop.
//!
//! This loop should be run as background task to fetch results from the scanner.

use crate::controller::quit_on_poison;
use std::sync::Arc;

use super::context::Context;

/// Defines the result fetching loop.
///
/// This loop should be run as background task to fetch results from the scanner.
pub async fn fetch<S, DB>(ctx: Arc<Context<S, DB>>)
where
    S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
    DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
{
    if let Some(cfg) = &ctx.result_config {
        let interval = cfg.0;
        tracing::debug!("Starting synchronization loop");
        loop {
            if *ctx.abort.read().unwrap() {
                tracing::trace!("aborting");
                break;
            }
            let scans = ctx.db.get_scan_ids().await;
            if let Err(e) = scans {
                tracing::warn!("Failed to get scans: {e}");
                continue;
            }
            let scans = scans.unwrap();

            for id in scans.iter() {
                // should never be none, probably makes sense to change scan_id
                // to not be an option and set a uuid on default when it is
                // missing on json serialization
                match ctx.db.get_status(id).await {
                    Ok(status) if status.is_done() => {
                        tracing::trace!("{id} skipping status = {}", status.status);
                    }
                    Ok(_) => {
                        let results = ctx.scanner.fetch_results(id.clone()).await;
                        match results {
                            Ok(fr) => {
                                tracing::trace!("{} fetched results", id);
                                // we panic when we fetched results but are unable to
                                // store them in the database.
                                // When this happens we effectively lost the results
                                // and need to escalate this.
                                ctx.db.append_fetched_result(id, fr).await.unwrap();
                            }
                            Err(crate::scan::Error::Poisoned) => {
                                quit_on_poison::<()>();
                            }
                            Err(e) => {
                                tracing::warn!("Failed to fetch results for {}: {e}", &id);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Unable to get status for {}: {}", id, e);
                    }
                }
            }
            std::thread::sleep(interval);
        }
    }
}
