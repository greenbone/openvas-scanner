// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines the result fetching loop.
//!
//! This loop should be run as background task to fetch results from the scanner.

use models::scanner::Scanner;

use crate::controller::quit_on_poison;
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
    if let Some(cfg) = &ctx.result_config {
        let interval = cfg.0;
        tracing::debug!("Starting synchronization loop");
        loop {
            if *ctx.abort.read().unwrap() {
                tracing::trace!("aborting");
                break;
            }
            // TODO change this use a scan scheduler later on
            // so that we don't have to iterate through all scans but just the ones that are
            // actually running
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
                        // TODO change fetch results to deliver all results of a given
                        // subset of ids so that it can decide itself if it gets results in
                        // bulk or per element.
                        let results = ctx.scanner.fetch_results(id.clone()).await;
                        match results {
                            Ok(fr) => {
                                tracing::trace!("{} fetched results", id);
                                // we panic when we fetched results but are unable to
                                // store them in the database.
                                // When this happens we effectively lost the results
                                // and need to escalate this.
                                ctx.db.append_fetched_result(vec![fr]).await.unwrap();
                            }
                            Err(models::scanner::Error::Poisoned) => {
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
