use std::{
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use greenbone_scanner_framework::GetVTsError;
use scannerlib::{
    feed,
    models::{FeedState, FeedType, VTData},
    nasl::FSPluginLoader,
    notus::{AdvisoryLoader, HashsumAdvisoryLoader, advisories::VulnerabilityData},
};
use sqlx::{Acquire, SqlitePool, query, query_scalar};

use crate::config::Config;
pub use crate::container_image_scanner::endpoints::vts::VTEndpoints as Endpoints;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Contains the hash values of the sha256sums for specific feeds
struct FeedHash {
    hash: String,
    path: PathBuf,
    typus: FeedType,
}

struct FeedSynchronizer {
    pool: SqlitePool,
    plugin_feed: PathBuf,
    advisory_feed: PathBuf,
    signature_check: bool,
    feed_state: Arc<RwLock<FeedState>>,
}

type FeedHashes = (String, String);

//TODO: move somewhere reusable if necessary
fn sumfile_hash<S>(path: S) -> Result<String, scannerlib::feed::VerifyError>
where
    S: AsRef<Path> + Clone + std::fmt::Debug + Sync + Send,
{
    let loader = scannerlib::nasl::FSPluginLoader::new(path);
    let verifier = scannerlib::feed::HashSumNameLoader::sha256(&loader)?;
    verifier.sumfile_hash()
}

trait Plugin: serde::Serialize {
    fn oid(&self) -> &str;
}

impl Plugin for VTData {
    fn oid(&self) -> &str {
        &self.oid
    }
}

impl Plugin for VulnerabilityData {
    fn oid(&self) -> &str {
        &self.adv.oid
    }
}

impl FeedSynchronizer {
    fn new(pool: SqlitePool, config: &Config, feed_state: Arc<RwLock<FeedState>>) -> Self {
        Self {
            pool,
            plugin_feed: config.feed.path.clone(),
            advisory_feed: config.notus.advisories_path.clone(),
            signature_check: config.feed.signature_check,
            feed_state,
        }
    }

    async fn calculate_hash(&self, path: PathBuf) -> Result<String, feed::VerifyError> {
        let signature_check = self.signature_check;
        tokio::task::spawn_blocking(move || {
            if signature_check {
                scannerlib::feed::check_signature(&path)?;
            }
            sumfile_hash(&path)
        })
        .await
        .unwrap()
    }

    async fn calculate_hashes(&self) -> Result<FeedHashes, feed::VerifyError> {
        let nasl_hash = self.calculate_hash(self.plugin_feed.clone()).await?;
        let advisories_hash = self.calculate_hash(self.advisory_feed.clone()).await?;
        Ok((nasl_hash, advisories_hash))
    }

    async fn knowns_hashes(&self) -> Result<FeedHashes, sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let plugin_hash = query_scalar("SELECT hash FROM feed WHERE type = 'nasl'")
            .fetch_optional(&mut *tx)
            .await?;
        let adv_hash = query_scalar("SELECT hash FROM feed WHERE type = 'advisories'")
            .fetch_optional(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok((
            plugin_hash.unwrap_or_default(),
            adv_hash.unwrap_or_default(),
        ))
    }
    async fn insert_feed_hash(
        &self,
        path: &Path,
        typus: FeedType,
        new_hash: &str,
    ) -> Result<(), sqlx::Error> {
        query("INSERT OR REPLACE INTO feed (hash, path, type) VALUES (?, ?, ?)")
            .bind(new_hash)
            .bind(path.to_string_lossy())
            .bind(typus.as_ref())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn store_plugin<T>(&self, feed_hash: &FeedHash, plugin: T) -> Result<(), GetVTsError>
    where
        T: Plugin,
    {
        let json = serde_json::to_vec(&plugin).map_err(error_vts_error)?;
        query(r#" INSERT INTO plugins ( oid, json_blob, feed_type) VALUES (?, ?, ?)"#)
            .bind(plugin.oid())
            .bind(&json)
            .bind(feed_hash.typus.as_ref())
            .execute(&self.pool)
            .await
            .map_err(error_vts_error)?;

        Ok(())
    }
    async fn change_state(&self, state: FeedState) {
        let fs = self.feed_state.clone();
        tokio::task::spawn_blocking(move || {
            let mut value = fs.write().unwrap();
            *value = state;
        })
        .await
        .unwrap()
    }

    async fn synchronize_json<F, T>(&self, hash: &FeedHash, f: F) -> Result<(), GetVTsError>
    where
        F: Fn(std::sync::mpsc::Sender<T>) -> Result<(), GetVTsError> + Send + 'static,
        T: Plugin + Send + Sync + 'static,
    {
        let (tx_async, mut rx_async) = tokio::sync::mpsc::channel::<T>(1);

        let (tx_blocking, rx_blocking) = std::sync::mpsc::channel::<T>();

        // background task to bridge between sync and async.
        // If we don't do that we may block the runtime
        let forwarder = tokio::spawn(async move {
            for item in rx_blocking {
                if tx_async.send(item).await.is_err() {
                    break;
                }
            }
        });

        let serde_handler = tokio::task::spawn_blocking(move || f(tx_blocking));

        while let Some(plugin) = rx_async.recv().await {
            self.store_plugin(hash, plugin).await?;
        }

        serde_handler
            .await
            .expect("tokio::task::spawn_blocking to be executed to run")
            .map_err(error_vts_error)?;
        forwarder
            .await
            .expect("tokio::task::spawn_blocking to be executed to run");

        Ok(())
    }

    async fn synchronize_plugins(&self, new_hash: String) -> Result<(), GetVTsError> {
        self.insert_feed_hash(&self.plugin_feed, FeedType::NASL, &new_hash)
            .await
            .map_err(error_vts_error)?;
        let mut path = self.plugin_feed.clone();
        let not_found = || {
            GetVTsError::External(Box::new(std::io::Error::other(
                "vt-metadata.json not found",
            )))
        };
        // if a feedpath is provided we expect a vt-metadata.json
        // if it is not a dir we assume it is the json file and continue
        if path.is_dir() {
            // TODO: validate hash_sum if required? For that we would need load the sha256sums, find
            // vt-metadata.json and then verify the sha256sum
            path.push("vt-metadata.json");
            if !path.is_file() {
                return Err(not_found());
            }
        }
        let hash = FeedHash {
            hash: new_hash,
            path: path.clone(),
            typus: FeedType::NASL,
        };

        self.synchronize_json(&hash, move |sender| {
            let file = std::fs::File::open(&path).map_err(|_| not_found())?;
            let reader = BufReader::new(file);
            for element in
                super::json_stream::iter_json_array::<VTData, _>(reader).filter_map(|x| x.ok())
            {
                if sender.send(element).is_err() {
                    break;
                }
            }

            Ok(())
        })
        .await
    }
    async fn synchronize_advisories(&self, new_hash: String) -> Result<(), GetVTsError> {
        self.insert_feed_hash(&self.advisory_feed, FeedType::Advisories, &new_hash)
            .await
            .map_err(error_vts_error)?;
        let path = self.advisory_feed.clone();
        let hash = FeedHash {
            hash: new_hash,
            path: path.clone(),
            typus: FeedType::Advisories,
        };

        self.synchronize_json::<_, VulnerabilityData>(&hash, move |sender| {
            let loader = FSPluginLoader::new(&path);
            let advisories_files =
                HashsumAdvisoryLoader::new(loader.clone()).map_err(error_vts_error)?;
            for filename in advisories_files
                .get_advisories()
                .map_err(error_vts_error)?
                .iter()
            {
                let advisories = advisories_files
                    .load_advisory(filename)
                    .map_err(error_vts_error)?;
                for adv in advisories.advisories {
                    let data = VulnerabilityData {
                        adv,
                        family: advisories.family.clone(),
                        filename: filename.to_owned(),
                    };

                    if sender.send(data).is_err() {
                        break;
                    }
                }
            }
            Ok(())
        })
        .await
    }

    async fn synchronize_feeds(&self) -> Result<(), GetVTsError> {
        let (plugin_hash, advisories_hash) =
            self.calculate_hashes().await.map_err(error_vts_error)?;
        let (known_plugin_hash, known_advisories_hash) =
            self.knowns_hashes().await.map_err(error_vts_error)?;
        if known_plugin_hash != plugin_hash || known_advisories_hash != advisories_hash {
            tracing::info!("Update feed metadata");
            self.change_state(FeedState::Syncing).await;
            if known_plugin_hash != plugin_hash {
                self.synchronize_plugins(plugin_hash.clone()).await?;
            }

            if known_advisories_hash != advisories_hash {
                self.synchronize_advisories(advisories_hash.clone())
                    .await
                    .map_err(error_vts_error)?;
            }

            tracing::info!("Updated feed metadata");
            self.change_state(FeedState::Synced(plugin_hash, advisories_hash))
                .await
        }

        Ok(())
    }
}

fn error_vts_error<T>(error: T) -> GetVTsError
where
    T: std::error::Error + Sync + Send + 'static,
{
    GetVTsError::External(Box::new(error))
}

/// Initializes endpoints, spawns background task for feed verification.
pub async fn init(pool: SqlitePool, config: &Config) -> (Arc<RwLock<FeedState>>, Endpoints) {
    let feed_state = Arc::new(RwLock::new(FeedState::default()));
    let endpoints = Endpoints::new(pool.clone(), feed_state.clone(), None);
    let feed_syncer = FeedSynchronizer::new(pool, config, feed_state.clone());
    let check_interval = config.feed.check_interval;

    tokio::spawn(async move {
        loop {
            tracing::debug!(next_check=?check_interval, "checking feed");

            if let Err(error) = feed_syncer.synchronize_feeds().await {
                tracing::warn!(%error, next_check=?check_interval, "Failed to synchronize feeds.");
            }

            tokio::time::sleep(check_interval).await;
        }
    });
    (feed_state, endpoints)
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use greenbone_scanner_framework::GetVts;
    use sqlx::SqlitePool;

    use super::*;
    use crate::{config::Config, setup_sqlite, vts::FeedSynchronizer};

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
        let endpoint = super::Endpoints::new(pool.clone(), feed_state.clone(), None);
        let synchronizer = FeedSynchronizer::new(pool.clone(), &config, feed_state);

        let oids = endpoint.get_oids("moep".into()).collect::<Vec<_>>().await;
        assert_eq!(oids.len(), 1);
        assert_eq!(
            oids.into_iter()
                .filter_map(|x| x.err())
                .filter(|x| matches!(x, GetVTsError::NotYetAvailable))
                .count(),
            1
        );

        synchronizer.synchronize_feeds().await?;
        // in the case that examples are changed, I don't want to change this test each time hence
        // we just verify if we got oids.
        let oids = endpoint.get_oids("moep".into()).collect::<Vec<_>>().await;
        assert!(!oids.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn plugin_shadow_copy() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let feed_state = Arc::new(RwLock::new(FeedState::default()));
        let endpoint = super::Endpoints::new(pool.clone(), feed_state.clone(), None);
        let synchronizer = FeedSynchronizer::new(pool.clone(), &config, feed_state.clone());

        let oids = endpoint.get_vts("moep".into()).collect::<Vec<_>>().await;
        assert_eq!(oids.len(), 1);
        assert_eq!(
            oids.into_iter()
                .filter_map(|x| x.err())
                .filter(|x| matches!(x, GetVTsError::NotYetAvailable))
                .count(),
            1
        );

        synchronizer.synchronize_feeds().await?;
        // in the case that examples are changed, I don't want to change this test each time hence
        // we just verify if we got oids.
        let oids = endpoint.get_vts("moep".into()).collect::<Vec<_>>().await;
        let oids_len = oids.len();
        assert!(!oids.is_empty());
        let filtered = oids.into_iter().filter_map(|x| x.ok()).count();
        assert_eq!(filtered, oids_len);
        Ok(())
    }
}
