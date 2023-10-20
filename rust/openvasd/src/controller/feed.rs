// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::sync::Arc;

use crate::feed::FeedIdentifier;

use super::context::Context;

pub async fn fetch<S, DB>(ctx: Arc<Context<S, DB>>)
where
    S: super::Scanner + 'static + std::marker::Send + std::marker::Sync,
    DB: crate::storage::Storage + 'static + std::marker::Send + std::marker::Sync,
{
    tracing::debug!("Starting VTS synchronization loop");
    if let Some(cfg) = &ctx.feed_config {
        let interval = cfg.verify_interval;
        let signature_check = cfg.signature_check;
        loop {
            let path = cfg.path.clone();
            if *ctx.abort.read().unwrap() {
                tracing::trace!("aborting");
                break;
            };
            let last_hash = ctx.db.feed_hash().await;
            let result = tokio::task::spawn_blocking(move || {
                let hash = match FeedIdentifier::sumfile_hash(&path) {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!("Failed to compute sumfile hash: {e:?}");
                        "".to_string()
                    }
                };

                if last_hash.is_empty() || last_hash.clone() != hash {
                    FeedIdentifier::from_feed(&path, signature_check).map(|x| (hash, x))
                } else {
                    Ok((String::new(), vec![]))
                }
            })
            .await
            .unwrap();
            match result {
                Ok((hash, oids)) => {
                    if !oids.is_empty() {
                        match ctx.db.push_oids(hash.clone(), oids).await {
                            Ok(_) => {
                                tracing::debug!("updated feed {hash}")
                            }
                            Err(e) => {
                                tracing::warn!("unable to fetch new oids, leaving the old: {e:?}")
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!("unable to fetch new oids, leaving the old: {e:?}"),
            };
            tokio::time::sleep(interval).await;
        }
    }
}
