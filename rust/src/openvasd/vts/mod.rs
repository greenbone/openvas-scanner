use std::{
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use futures::StreamExt;
use greenbone_scanner_framework::GetVTsError;
use scannerlib::{
    PinBoxFut, feed,
    models::{FeedState, FeedType, VTData},
    nasl::FSPluginLoader,
    notus::{AdvisoryLoader, HashsumAdvisoryLoader, advisories::VulnerabilityData},
};
use sqlx::{Row, SqlitePool, query, sqlite::SqliteRow};
use tokio::sync::broadcast::Sender;

use crate::config::Config;
pub mod orchestrator;
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

    fn calculated_hashes(&self) -> PinBoxFut<Result<FeedHashes, orchestrator::WorkerError>> {
        let signature_check = self.signature_check;
        let plugin_feed = self.plugin_feed.clone();
        let advisory_feed = self.advisory_feed.clone();
        Box::pin(async move {
            let nasl_hash = Self::calculate_hash(signature_check, plugin_feed).await?;
            let advisories_hash = Self::calculate_hash(signature_check, advisory_feed).await?;
            Ok((nasl_hash, advisories_hash))
        })
    }

    fn update_feed(
        &self,
        kind: FeedType,
        new_hash: String,
    ) -> PinBoxFut<Result<(), orchestrator::WorkerError>> {
        let pool = self.pool.clone();
        let adv_path = self.advisory_feed.clone();
        let nasl_path = self.plugin_feed.clone();
        Box::pin(async move {
            match kind {
                FeedType::Products => tracing::debug!(?kind, "Not supported, ignoring."),
                FeedType::Advisories => {
                    Self::synchronize_advisories(&pool, adv_path, new_hash).await?
                }
                FeedType::NASL => Self::synchronize_plugins(&pool, nasl_path, new_hash).await?,
            };
            Ok(())
        })
    }
}

impl FeedSynchronizer {
    fn new(pool: SqlitePool, config: &Config) -> Self {
        Self {
            pool,
            plugin_feed: config.feed.path.clone(),
            advisory_feed: config.notus.advisories_path.clone(),
            signature_check: config.feed.signature_check,
        }
    }

    async fn calculate_hash(
        signature_check: bool,
        path: PathBuf,
    ) -> Result<String, feed::VerifyError> {
        tokio::task::spawn_blocking(move || {
            if signature_check {
                scannerlib::feed::check_signature(&path)?;
            }
            sumfile_hash(&path)
        })
        .await
        .unwrap()
    }

    async fn insert_feed_hash(
        pool: &SqlitePool,
        path: &str,
        typus: FeedType,
        new_hash: &str,
    ) -> Result<(), sqlx::Error> {
        query("INSERT OR REPLACE INTO feed (hash, path, type) VALUES (?, ?, ?)")
            .bind(new_hash)
            .bind(path)
            .bind(typus.as_ref())
            .execute(pool)
            .await?;
        Ok(())
    }

    async fn store_plugin<T>(
        pool: &SqlitePool,
        feed_hash: &FeedHash,
        plugin: T,
    ) -> Result<(), GetVTsError>
    where
        T: Plugin,
    {
        let json = serde_json::to_vec(&plugin).map_err(error_vts_error)?;
        query(r#" INSERT INTO plugins ( oid, json_blob, feed_type) VALUES (?, ?, ?)"#)
            .bind(plugin.oid())
            .bind(&json)
            .bind(feed_hash.typus.as_ref())
            .execute(pool)
            .await
            .map_err(error_vts_error)?;

        Ok(())
    }

    async fn synchronize_json<F, T>(
        pool: &SqlitePool,
        hash: &FeedHash,
        f: F,
    ) -> Result<(), GetVTsError>
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
            Self::store_plugin(pool, hash, plugin).await?;
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

    async fn synchronize_plugins(
        pool: &SqlitePool,
        mut path: PathBuf,
        new_hash: String,
    ) -> Result<(), GetVTsError> {
        Self::insert_feed_hash(
            pool,
            path.to_str().unwrap_or_default(),
            FeedType::NASL,
            &new_hash,
        )
        .await
        .map_err(error_vts_error)?;
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

        Self::synchronize_json(pool, &hash, move |sender| {
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
    // TODO: create struct to simplify parameter?
    async fn synchronize_advisories(
        pool: &SqlitePool,
        path: PathBuf,
        new_hash: String,
    ) -> Result<(), GetVTsError> {
        Self::insert_feed_hash(
            pool,
            path.to_str().unwrap_or_default(),
            FeedType::Advisories,
            &new_hash,
        )
        .await
        .map_err(error_vts_error)?;
        let hash = FeedHash {
            hash: new_hash,
            path: path.clone(),
            typus: FeedType::Advisories,
        };

        Self::synchronize_json::<_, VulnerabilityData>(pool, &hash, move |sender| {
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
}

fn error_vts_error<T>(error: T) -> GetVTsError
where
    T: std::error::Error + Sync + Send + 'static,
{
    GetVTsError::External(Box::new(error))
}

/// Initializes endpoints, spawns background task for feed verification.
pub async fn init(
    pool: SqlitePool,
    config: &Config,
    snapshot: Arc<RwLock<FeedState>>,
) -> (Sender<orchestrator::Message>, Endpoints) {
    let endpoints = Endpoints::new(pool.clone(), snapshot.clone(), None);
    let worker = FeedSynchronizer::new(pool, config);
    let sender =
        orchestrator::Orchestrator::init(config.feed.check_interval, snapshot, worker).await;
    (sender, endpoints)
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
