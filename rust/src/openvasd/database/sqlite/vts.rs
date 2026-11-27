// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::PathBuf;

use crate::database::sqlite::insert_values_chunked;
use crate::vts::FeedHashes;
use crate::vts::Plugin;
use async_trait::async_trait;
use futures::StreamExt;
use scannerlib::models::{FeedType, VTData};
use scannerlib::nasl::utils::mtime::{MtimeCheckError, MtimeStatus, compute_mtime};
use scannerlib::notus::advisories::VulnerabilityData;
use scannerlib::storage::Retriever;
use scannerlib::storage::error::StorageError;
use scannerlib::storage::items::nvt::{FileName, Oid};
use sqlx::Row;
use sqlx::SqlitePool;
use sqlx::query;
use sqlx::sqlite::SqliteRow;

use crate::api::stream::StreamResult;
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
    // Feed path necessary for checking the file mtime when signature is enabled
    feed_root: PathBuf,
    // Mtime is stored and later checked only if signature check is enabled.
    signature_check: bool,
}

impl SqlPluginStorage {
    pub fn with_plugin_feed(pool: SqlitePool, feed_root: PathBuf, signature_check: bool) -> Self {
        SqlPluginStorage {
            pool,
            feed_root,
            signature_check,
        }
    }
}

impl PluginFetcher for SqlPluginStorage {
    fn get_oids(&self) -> StreamResult<String, WorkerError> {
        let result = query("SELECT oid FROM plugins where oid NOT LIKE '%inc' ORDER BY oid")
            .fetch(&self.pool)
            .map(|row| row.map(|e| e.get("oid")).map_err(WorkerError::Cache));
        Box::pin(result)
    }

    fn get_vts(&self) -> StreamResult<scannerlib::models::VTData, WorkerError> {
        let result = query("SELECT feed_type, json_blob FROM plugins WHERE oid NOT LIKE '%inc'")
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
        Box::pin(result)
    }
}

impl PluginStorer for SqlPluginStorage {
    async fn prepare_feed(&self, hash: &FeedHash) -> Result<(), WorkerError> {
        let pending = crate::vts::pending_hash(hash);
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        query(
            "INSERT INTO feed (hash, path, type) VALUES (?, ?, ?)
         ON CONFLICT(type) DO UPDATE SET hash = excluded.hash, path = excluded.path",
        )
        .bind(&pending.hash)
        .bind(pending.path.to_str().unwrap_or_default())
        .bind(pending.typus.as_ref())
        .execute(&mut *tx)
        .await?;
        query("DELETE FROM plugins WHERE feed_type = ?")
            .bind(hash.typus.as_ref())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn store_plugins<T>(&self, hash: &FeedHash, plugins: Vec<T>) -> Result<(), WorkerError>
    where
        T: Plugin + Send + Sync + 'static,
    {
        // Prepare everything first, so the write lock is only held for the INSERTs
        let rows = plugins
            .iter()
            .map(|p| {
                let hashsum = p.hashsum();
                let mtime = match (hash.typus, p.vulnerability_test()) {
                    (FeedType::NASL, Some(vt)) => {
                        compute_mtime(&self.feed_root.join(&vt.filename), Some(hashsum))?
                    }
                    _ => 0,
                };
                Ok((p.oid(), serde_json::to_vec(p)?, hashsum, mtime))
            })
            .collect::<Result<Vec<_>, WorkerError>>()?;

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        insert_values_chunked(
            &mut *tx,
            "INSERT INTO plugins (oid, json_blob, feed_type, hashsum, mtime) ",
            |mut b, (oid, json, hashsum, mtime)| {
                b.push_bind(*oid)
                    .push_bind(json.as_slice())
                    .push_bind(hash.typus.as_ref())
                    .push_bind(*hashsum)
                    .push_bind(*mtime);
            },
            &rows,
            5,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn store_hash(&self, hash: &FeedHash) -> Result<(), WorkerError> {
        let path = hash.path.to_str().unwrap_or_default();
        query(
            "INSERT INTO feed (hash, path, type) VALUES (?, ?, ?)
                 ON CONFLICT(type) DO UPDATE SET hash = excluded.hash, path = excluded.path",
        )
        .bind(&hash.hash)
        .bind(path)
        .bind(hash.typus.as_ref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl SqlPluginStorage {
    // Check that the file mtime is not newer than the value stored.
    pub async fn check_mtime(&self, filename: &str) -> Result<MtimeStatus, MtimeCheckError> {
        if !self.signature_check {
            return Ok(MtimeStatus::UpToDate);
        }

        let row =
            query("SELECT mtime FROM plugins WHERE json_extract(json_blob, '$.filename') = ?")
                .bind(filename)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| MtimeCheckError::Io(filename.to_string(), e.to_string()))?;

        let stored_mtime = row
            .as_ref()
            .map(|r| r.get::<i64, _>("mtime"))
            .filter(|s| *s != 0)
            .ok_or_else(|| MtimeCheckError::NotFound(filename.to_string()))?;

        let filename = self.feed_root.join(filename);
        let current_mtime = compute_mtime(&self.feed_root.join(&filename), None)?;

        if current_mtime > stored_mtime {
            return Ok(MtimeStatus::Modified {
                file: filename.clone().into_string().unwrap(),
                stored: stored_mtime,
                current: current_mtime,
            });
        }

        Ok(MtimeStatus::UpToDate)
    }
}

fn deserialize_vt(row: &SqliteRow) -> Result<Option<VTData>, StorageError> {
    let feed_type: &str = row.get("feed_type");
    let json: &[u8] = row.get("json_blob");
    match feed_type {
        "nasl" => serde_json::from_slice::<VTData>(json)
            .map(Some)
            .map_err(|e| StorageError::Dirty(e.to_string())),
        "advisories" => serde_json::from_slice::<VulnerabilityData>(json)
            .map(|v| Some(v.into()))
            .map_err(|e| StorageError::Dirty(e.to_string())),
        other => Err(StorageError::Dirty(format!("unknown feed_type: {other}"))),
    }
}

#[async_trait]
impl Retriever<Oid> for SqlPluginStorage {
    type Item = VTData;
    async fn retrieve(&self, key: &Oid) -> Result<Option<Self::Item>, StorageError> {
        let row = query("SELECT feed_type, json_blob FROM plugins WHERE oid = ?")
            .bind(&key.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::Dirty(e.to_string()))?;
        row.as_ref()
            .map(deserialize_vt)
            .transpose()
            .map(Option::flatten)
    }
}

#[async_trait]
impl Retriever<FileName> for SqlPluginStorage {
    type Item = VTData;
    async fn retrieve(&self, key: &FileName) -> Result<Option<Self::Item>, StorageError> {
        let row = query(
            "SELECT feed_type, json_blob FROM plugins WHERE json_extract(json_blob, '$.filename') = ?",
        )
        .bind(&key.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Dirty(e.to_string()))?;
        row.as_ref()
            .map(deserialize_vt)
            .transpose()
            .map(Option::flatten)
    }
}

impl orchestrator::Worker for FeedSynchronizer {
    async fn cached_hashes(&self) -> Result<Option<FeedHashes>, orchestrator::WorkerError> {
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
        let rofl = (
            transform(fetched.next().await),
            transform(fetched.next().await),
        );
        Ok(match rofl {
            (None, None) => None,
            (advisories, nasl) => Some((nasl.unwrap_or_default(), advisories.unwrap_or_default())),
        })
    }

    async fn update_feed(
        &self,
        kind: FeedType,
        new_hash: String,
    ) -> Result<(), orchestrator::WorkerError> {
        let path = match kind {
            FeedType::Products | FeedType::Advisories => self.advisory_feed(),
            FeedType::NASL => self.plugin_feed(),
        };
        let feed_hash = FeedHash {
            hash: new_hash,
            path,
            typus: kind,
        };
        let feed_integrity_check = self.signature_check;
        crate::vts::synchronize_feed(&self.plugin_storer, feed_hash, feed_integrity_check).await
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
            plugin_storer: SqlPluginStorage {
                pool,
                feed_root: config.feed.path.clone(),
                signature_check: config.feed.signature_check,
            },
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::{Arc, RwLock};

    use crate::{
        api::{error::ApiError, states::Feed},
        database::sqlite::DbGuard,
    };
    use scannerlib::models::FeedState;

    use futures_util::StreamExt;

    use crate::database::sqlite;

    use super::*;

    impl From<SqlitePool> for SqlPluginStorage {
        fn from(value: SqlitePool) -> Self {
            SqlPluginStorage {
                pool: value,
                feed_root: PathBuf::new(),
                signature_check: false,
            }
        }
    }

    async fn create_pool() -> anyhow::Result<(Config, SqlitePool, DbGuard)> {
        let nasl = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/nasl").into();
        let notus = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/feed/notus/advisories"
        )
        .into();
        let feed = crate::config::Feed {
            path: nasl,
            signature_check: false,
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
        let pool = sqlite::init(&config).await?;
        let guard = DbGuard::new(pool.clone());

        Ok((config, pool, guard))
    }

    #[tokio::test]
    async fn get_oids() -> anyhow::Result<()> {
        let (config, pool, _guard) = create_pool().await?;
        let feed_state = Arc::new(RwLock::new(FeedState::default()));

        let synchronizer = FeedSynchronizer::new(pool.clone(), &config);
        let feed = Feed::new(SqlPluginStorage::from(pool.clone()), feed_state.clone());

        assert!(matches!(feed.get_oids(), Err(ApiError::FeedNotSynced)));

        orchestrator::test::verify_allowed_for(
            synchronizer,
            feed_state,
            &[FeedType::NASL, FeedType::Advisories],
        )
        .await?;

        // in the case that examples are changed, I don't want to change this test each time hence
        // we just verify if we got oids.
        let oids = feed.get_oids()?.collect::<Vec<_>>().await;
        let oids = oids.into_iter().filter_map(|x| x.ok()).collect::<Vec<_>>();
        assert!(!oids.is_empty());

        let vts = feed.get_vts()?.collect::<Vec<_>>().await;
        let vts = vts.into_iter().filter_map(|x| x.ok()).collect::<Vec<_>>();
        assert!(!vts.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn resync_replaces_plugins() -> anyhow::Result<()> {
        use orchestrator::Worker;
        let (config, pool, _guard) = create_pool().await?;
        let synchronizer = FeedSynchronizer::new(pool.clone(), &config);
        let count = || async {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM plugins")
                .fetch_one(&pool)
                .await
        };

        synchronizer
            .update_feed(FeedType::NASL, "first".into())
            .await?;
        let first = count().await?;
        assert!(first > 0);

        // must not fail with a UNIQUE violation and must not duplicate anything
        synchronizer
            .update_feed(FeedType::NASL, "second".into())
            .await?;
        assert_eq!(count().await?, first);

        let hash: String = sqlx::query_scalar("SELECT hash FROM feed WHERE type = 'nasl'")
            .fetch_one(&pool)
            .await?;
        assert_eq!(hash, "second");
        Ok(())
    }
}
