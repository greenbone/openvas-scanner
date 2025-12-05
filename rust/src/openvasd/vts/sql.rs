use std::path::PathBuf;

use super::FeedHashes;
use super::Plugin;
use super::error_vts_error;
use futures::StreamExt;
use scannerlib::PinBoxFut;
use scannerlib::models::FeedType;
use scannerlib::notus::advisories::VulnerabilityData;
use sqlx::Row;
use sqlx::SqlitePool;
use sqlx::query;
use sqlx::sqlite::SqliteRow;

use crate::config::Config;
use crate::vts::FeedHash;
use crate::vts::PluginFetcher;
use crate::vts::PluginStorer;
use crate::vts::orchestrator;
use crate::vts::orchestrator::WorkerError;

pub struct FeedSynchronizer {
    pool: SqlitePool,
    plugin_feed: PathBuf,
    advisory_feed: PathBuf,
    signature_check: bool,
    plugin_storer: SqlPluginStorage,
}

#[derive(Debug, Clone)]
pub struct SqlPluginStorage {
    pool: SqlitePool,
}

impl From<SqlitePool> for SqlPluginStorage {
    fn from(value: SqlitePool) -> Self {
        SqlPluginStorage { pool: value }
    }
}

impl PluginFetcher for SqlPluginStorage {
    fn get_oids(&self) -> greenbone_scanner_framework::StreamResult<'static, String, WorkerError> {
        let result = query("SELECT oid FROM plugins ORDER BY oid")
            .fetch(&self.pool)
            .map(|row| row.map(|e| e.get("oid")).map_err(WorkerError::Cache));
        Box::new(result)
    }

    fn get_vts(
        &self,
    ) -> greenbone_scanner_framework::StreamResult<'static, scannerlib::models::VTData, WorkerError>
    {
        let result = query("SELECT feed_type, json_blob FROM plugins")
            .fetch(&self.pool)
            .map(|row| {
                let r = row
                    .map(|x| match x.get("feed_type") {
                        "advisories" => {
                            serde_json::from_slice::<VulnerabilityData>(x.get("json_blob"))
                                .map_err(WorkerError::Serialization)
                                .map(|x| x.into())
                        }
                        _ => serde_json::from_slice(x.get("json_blob"))
                            .map_err(WorkerError::Serialization),
                    })
                    .map_err(WorkerError::Cache);
                match r {
                    Ok(Ok(x)) => Ok(x),
                    Ok(e) => e,
                    Err(e) => Err(e),
                }
            });
        Box::new(result)
    }
}

impl PluginStorer for SqlPluginStorage {
    fn store_plugin<T>(&self, hash: &FeedHash, plugin: T) -> PinBoxFut<Result<(), WorkerError>>
    where
        T: Plugin + Send + Sync + 'static,
    {
        let pool = self.pool.clone();
        let typus = hash.typus;
        Box::pin(async move {
            let json = serde_json::to_vec(&plugin).map_err(error_vts_error)?;
            query(r#" INSERT INTO plugins ( oid, json_blob, feed_type) VALUES (?, ?, ?)"#)
                .bind(plugin.oid())
                .bind(&json)
                .bind(typus.as_ref())
                .execute(&pool)
                .await
                .map_err(error_vts_error)?;

            Ok(())
        })
    }

    fn store_hash(&self, hash: &FeedHash) -> PinBoxFut<Result<(), WorkerError>> {
        let pool = self.pool.clone();
        let path = hash.path.to_str().unwrap_or_default().to_string();
        let ht = hash.typus;
        let hash = hash.hash.clone();
        Box::pin(async move {
            query("INSERT OR REPLACE INTO feed (hash, path, type) VALUES (?, ?, ?)")
                .bind(hash)
                .bind(path)
                .bind(ht.as_ref())
                .execute(&pool)
                .await
                .map_err(error_vts_error)?;
            Ok(())
        })
    }
}

impl orchestrator::Worker for FeedSynchronizer {
    fn cached_hashes(&self) -> PinBoxFut<Result<Option<FeedHashes>, orchestrator::WorkerError>> {
        let mut fetched =
            query("SELECT hash FROM feed WHERE type = 'nasl' OR type = 'advisories' ORDER BY type")
                .fetch(&self.pool);
        let transform = |x: Option<Result<SqliteRow, sqlx::error::Error>>| {
            if let Some(Ok(x)) = x {
                Some(x.get::<String, _>("hash"))
            } else {
                None
            }
        };

        Box::pin(async move {
            let rofl = (
                transform(fetched.next().await),
                transform(fetched.next().await),
            );
            Ok(match rofl {
                (None, None) => None,
                (advisories, nasl) => {
                    Some((nasl.unwrap_or_default(), advisories.unwrap_or_default()))
                }
            })
        })
    }

    fn update_feed(
        &self,
        kind: FeedType,
        new_hash: String,
    ) -> PinBoxFut<Result<(), orchestrator::WorkerError>> {
        let ps = self.plugin_storer.clone();
        let path = match kind {
            FeedType::Products | FeedType::Advisories => self.advisory_feed(),
            FeedType::NASL => self.plugin_feed(),
        };
        let feed_hash = FeedHash {
            hash: new_hash,
            path,
            typus: kind,
        };
        let verify = self.signature_check;
        Box::pin(async move { super::synchronize_feed(&ps, feed_hash, verify).await })
    }

    fn signature_check(&self) -> bool {
        self.signature_check
    }

    fn plugin_feed(&self) -> PathBuf {
        self.plugin_feed.clone()
    }

    fn advisory_feed(&self) -> PathBuf {
        self.advisory_feed.clone()
    }
}

impl FeedSynchronizer {
    pub fn new(pool: SqlitePool, config: &Config) -> Self {
        Self {
            pool: pool.clone(),
            plugin_feed: config.feed.path.clone(),
            advisory_feed: config.notus.advisories_path.clone(),
            signature_check: config.feed.signature_check,
            plugin_storer: SqlPluginStorage { pool },
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::{Arc, RwLock};

    use crate::container_image_scanner::endpoints::vts::VTEndpoints;
    use greenbone_scanner_framework::models::FeedState;
    use greenbone_scanner_framework::{GetVTsError, GetVts};

    use crate::setup_sqlite;

    use super::*;

    async fn create_pool() -> crate::Result<(Config, SqlitePool)> {
        let nasl = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/nasl").into();
        let notus = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/feed/notus/advisories"
        )
        .into();
        let feed = crate::config::Feed {
            path: nasl,
            ..Default::default()
        };
        let notus = crate::config::Notus {
            advisories_path: notus,
            ..Default::default()
        };

        let config = Config {
            feed,
            notus,
            ..Default::default()
        };
        let pool = setup_sqlite(&config).await?;

        Ok((config, pool))
    }

    #[tokio::test]
    async fn get_oids() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let feed_state = Arc::new(RwLock::new(FeedState::default()));
        let endpoint = VTEndpoints::new(
            SqlPluginStorage::from(pool.clone()),
            feed_state.clone(),
            None,
        );
        let synchronizer = FeedSynchronizer::new(pool.clone(), &config);

        let oids = endpoint.get_oids("moep".into()).collect::<Vec<_>>().await;
        assert_eq!(oids.len(), 1);
        assert_eq!(
            oids.into_iter()
                .filter_map(|x| x.err())
                .filter(|x| matches!(x, GetVTsError::NotYetAvailable))
                .count(),
            1
        );

        orchestrator::test::verify_allowed_for(
            synchronizer,
            feed_state,
            &[FeedType::NASL, FeedType::Advisories],
        )
        .await?;

        // in the case that examples are changed, I don't want to change this test each time hence
        // we just verify if we got oids.
        let oids = endpoint.get_oids("moep".into()).collect::<Vec<_>>().await;
        let oids = oids.into_iter().filter_map(|x| x.ok()).collect::<Vec<_>>();
        dbg!(&oids);
        assert!(!oids.is_empty());

        let vts = endpoint.get_vts("moep".into()).collect::<Vec<_>>().await;
        let vts = vts.into_iter().filter_map(|x| x.ok()).collect::<Vec<_>>();
        assert!(!vts.is_empty());
        Ok(())
    }
}
