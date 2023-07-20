// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines the result fetching loop.
//!
//! This loop should be run as background task to fetch results from the scanner.
use crate::controller::quit_on_poison;
use std::sync::Arc;

use crate::scan::ScanResultFetcher;

use super::context::Context;

/// Defines the result fetching loop.
///
/// This loop should be run as background task to fetch results from the scanner.
pub async fn fetch<S>(ctx: Arc<Context<S>>)
where
    S: ScanResultFetcher + std::marker::Send + std::marker::Sync + 'static + std::fmt::Debug,
{
    if let Some(cfg) = &ctx.result_config {
        let interval = cfg.0;
        tracing::debug!("Starting synchronization loop");
        loop {
            if *ctx.abort.read().unwrap() {
                tracing::trace!("aborting");
                break;
            }
            let ls = match ctx.scans.read() {
                Ok(ls) => ls.clone(),
                Err(_) => quit_on_poison(),
            };
            let scans = ls.clone();
            drop(ls);
            for (id, prgs) in scans.iter() {
                if prgs.status.is_done() {
                    tracing::trace!("{id} skipping status = {}", prgs.status.status);
                    continue;
                }
                match ctx.scanner.fetch_results(prgs) {
                    Ok(fr) => {
                        tracing::trace!("{id} fetched results");
                        let mut progress = prgs.clone();
                        progress.append_results(fr).await;
                        let a = progress.results.lock().await.len();
                        tracing::trace!("results length {:?}", a);
                        let mut ls = match ctx.scans.write() {
                            Ok(ls) => ls,
                            Err(_) => quit_on_poison(),
                        };
                        ls.insert(progress.scan.scan_id.clone().unwrap(), progress);
                        drop(ls);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch results for {id}: {e}");
                    }
                }
            }
            std::thread::sleep(interval);
        }
        
    }
}
