// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::Arc;

use models::scanner::Scanner;

use crate::{
    feed::FeedIdentifier,
    storage::{FeedHash, NVTStorer as _},
};

use super::context::Context;

async fn changed_hash(signature_check: bool, feeds: &[FeedHash]) -> Result<Vec<FeedHash>, ()> {
    let mut result = Vec::with_capacity(feeds.len());
    for h in feeds {
        if signature_check {
            if let Err(err) = feed::verify::check_signature(&h.path) {
                tracing::warn!(
                    sumsfile=%h.path.display(),
                    error=%err,
                    "Signature is incorrect, skipping",
                );
                return Err(());
            }
        }

        let path = h.path.clone();
        let hash = tokio::task::spawn_blocking(move || match FeedIdentifier::sumfile_hash(&path) {
            Ok(h) => h,
            Err(mut e) => {
                e.key = path.to_str().unwrap_or_default().to_string();

                tracing::warn!(%e, "Failed to compute sumfile hash");
                "".to_string()
            }
        })
        .await
        .unwrap();
        if hash != h.hash {
            let mut nh = h.clone();
            nh.hash = hash;
            result.push(nh);
        }
    }
    Ok(result)
}

pub async fn fetch<S, DB>(ctx: Arc<Context<S, DB>>)
where
    S: Scanner + 'static + std::marker::Send + std::marker::Sync,
    DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
{
    tracing::debug!("Starting VTS synchronization loop");
    if let Some(cfg) = &ctx.feed_config {
        let interval = cfg.check_interval;
        let signature_check = cfg.signature_check;
        loop {
            if *ctx.abort.read().unwrap() {
                tracing::trace!("aborting");
                break;
            };
            let last_hash = ctx.scheduler.feed_hash().await;
            if let Ok(nh) = changed_hash(signature_check, &last_hash).await {
                if !nh.is_empty() {
                    if let Err(err) = ctx.scheduler.synchronize_feeds(nh).await {
                        tracing::warn!(%err, "Unable to sync feed")
                    }
                }
            }

            tokio::time::sleep(interval).await;
        }
    }
}
