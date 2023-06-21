// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::sync::Arc;

use crate::feed::FeedIdentifier;

use super::context::Context;
use super::quit_on_poison;

pub async fn fetch<S>(ctx: Arc<Context<S>>)
where
    S: std::marker::Send + std::marker::Sync + 'static,
{
    if let Some(cfg) = &ctx.feed_config {
        let interval = cfg.verify_interval;
        let path = cfg.path.clone();
        tracing::debug!("Starting VTS synchronization loop");
        tokio::task::spawn_blocking(move || loop {
            if *ctx.abort.read().unwrap() {
                tracing::trace!("aborting");
                break;
            }
            let last_hash = match ctx.oids.read() {
                Ok(vts) => vts.0.clone(),
                Err(_) => quit_on_poison(),
            };
            let hash = match FeedIdentifier::sumfile_hash(&path) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!("Failed to compute sumfile hash: {e:?}");
                    "".to_string()
                }
            };
            if last_hash != hash {
                tracing::debug!("VTS hash {last_hash} changed {hash}, updating");
                match FeedIdentifier::from_feed(&path) {
                    Ok(o) => {
                        let mut oids = match ctx.oids.write() {
                            Ok(oids) => oids,
                            Err(_) => quit_on_poison(),
                        };
                        tracing::trace!(
                            "VTS hash changed updated (old: {}, new: {})",
                            oids.1.len(),
                            o.len()
                        );
                        *oids = (hash, o);
                    }
                    Err(e) => {
                        tracing::warn!("unable to fetch new oids, leaving the old: {e:?}")
                    }
                };
            }

            std::thread::sleep(interval);
        })
        .await
        .unwrap();
    }
}
