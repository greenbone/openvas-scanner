use std::io::BufReader;
use std::sync::RwLock;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use greenbone_scanner_framework::{GetVTsError, StreamResult};
use scannerlib::PinBoxFut;
use scannerlib::nasl::FSPluginLoader;
use scannerlib::notus::{AdvisoryLoader, HashsumAdvisoryLoader};
use scannerlib::{
    models::{FeedState, FeedType, VTData},
    notus::advisories::VulnerabilityData,
};
use sqlx::SqlitePool;

use crate::config::{Config, ScannerType};
pub mod orchestrator;
pub mod redis;
pub mod sql;
pub use crate::container_image_scanner::endpoints::vts::VTEndpoints as Endpoints;
use crate::json_stream;
use crate::vts::orchestrator::WorkerError;
use crate::vts::sql::SqlPluginStorage;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Contains the hash values of the sha256sums for specific feeds
struct FeedHash {
    hash: String,
    path: PathBuf,
    typus: FeedType,
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
    fn advisory(&self) -> Option<&VulnerabilityData>;
    fn vulnerability_test(&self) -> Option<&VTData>;
}

impl Plugin for VTData {
    fn oid(&self) -> &str {
        &self.oid
    }

    fn advisory(&self) -> Option<&VulnerabilityData> {
        None
    }

    fn vulnerability_test(&self) -> Option<&VTData> {
        Some(self)
    }
}

impl Plugin for VulnerabilityData {
    fn oid(&self) -> &str {
        &self.adv.oid
    }

    fn advisory(&self) -> Option<&VulnerabilityData> {
        Some(self)
    }

    fn vulnerability_test(&self) -> Option<&VTData> {
        None
    }
}

fn error_vts_error<T>(error: T) -> GetVTsError
where
    T: std::error::Error + Sync + Send + 'static,
{
    GetVTsError::External(Box::new(error))
}

pub trait PluginFetcher {
    fn get_oids(&self) -> StreamResult<'static, String, WorkerError>;

    fn get_vts(&self) -> StreamResult<'static, VTData, WorkerError>;
}

pub async fn _init<F, W>(
    config: &Config,
    fetcher: F,
    worker: W,
    snapshot: Arc<RwLock<FeedState>>,
) -> (orchestrator::Communicator, Endpoints)
where
    F: PluginFetcher + Send + Sync + 'static,
    W: orchestrator::Worker + Send + Sync + 'static,
{
    let communicator =
        orchestrator::Orchestrator::init(config.feed.check_interval, snapshot.clone(), worker)
            .await;

    (communicator, Endpoints::new(fetcher, snapshot, None))
}
/// Initializes endpoints, spawns background task for feed verification.
pub async fn init(
    pool: SqlitePool,
    config: &Config,
    snapshot: Arc<RwLock<FeedState>>,
) -> (orchestrator::Communicator, Endpoints) {
    match config.scanner.scanner_type {
        ScannerType::Openvas => {
            let fetcher = redis::RedisPluginHandler::from(config);
            let worker = redis::FeedSynchronizer::from(config);
            _init(config, fetcher, worker, snapshot).await
        }
        // For OSPD we actually don't need a communicator at all, however as we are facing out OSPD
        // altogether the effort of getting rid of that seems not worth it.
        ScannerType::Openvasd | ScannerType::Ospd => {
            let fetcher = SqlPluginStorage::from(pool.clone());
            let worker = sql::FeedSynchronizer::new(pool, config);
            _init(config, fetcher, worker, snapshot).await
        }
    }
}

trait PluginStorer {
    fn store_hash(&self, hash: &FeedHash) -> PinBoxFut<Result<(), WorkerError>>;
    fn store_plugin<T>(&self, hash: &FeedHash, plugin: T) -> PinBoxFut<Result<(), WorkerError>>
    where
        T: Plugin + Send + Sync + 'static;
}

async fn synchronize_json<F, T, PS>(ps: &PS, hash: &FeedHash, f: F) -> Result<(), WorkerError>
where
    F: Fn(std::sync::mpsc::Sender<T>) -> Result<(), WorkerError> + Send + 'static,
    T: Plugin + Send + Sync + 'static,
    PS: PluginStorer + Send + Sync + 'static,
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
        ps.store_plugin(hash, plugin).await?;
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

async fn synchronize_feed<T>(
    ps: &T,
    feed_hash: FeedHash,
    signature_check: bool,
) -> Result<(), WorkerError>
where
    T: PluginStorer + Send + Sync + 'static,
{
    match feed_hash.typus {
        FeedType::Products => tracing::debug!(?feed_hash.typus, "Not supported, ignoring."),
        FeedType::Advisories => {
            ps.store_hash(&feed_hash).await?;
            synchronize_advisories(ps, feed_hash.path, feed_hash.hash, signature_check).await?
        }
        FeedType::NASL => {
            ps.store_hash(&feed_hash).await?;
            synchronize_plugins(ps, feed_hash.path, feed_hash.hash).await?
        }
    };
    Ok(())
}

async fn synchronize_advisories<T>(
    ps: &T,
    path: PathBuf,
    new_hash: String,
    signature_check: bool,
) -> Result<(), WorkerError>
where
    T: PluginStorer + Send + Sync + 'static,
{
    let hash = FeedHash {
        hash: new_hash,
        path: path.clone(),
        typus: FeedType::Advisories,
    };

    synchronize_json::<_, VulnerabilityData, _>(ps, &hash, move |sender| {
        let loader = FSPluginLoader::new(&path);
        let advisories_files =
            HashsumAdvisoryLoader::new(loader.clone()).map_err(error_vts_error)?;
        for filename in advisories_files
            .get_advisories()
            .map_err(error_vts_error)?
            .iter()
        {
            let advisories = advisories_files
                .load_advisory(filename, signature_check)
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

async fn synchronize_plugins<T>(
    ps: &T,
    mut path: PathBuf,
    new_hash: String,
) -> Result<(), WorkerError>
where
    T: PluginStorer + Send + Sync + 'static,
{
    let not_found = || {
        WorkerError::Sync(GetVTsError::External(Box::new(std::io::Error::other(
            "vt-metadata.json not found",
        ))))
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

    synchronize_json(ps, &hash, move |sender| {
        let file = std::fs::File::open(&path).map_err(|_| not_found())?;
        let reader = BufReader::new(file);
        for element in json_stream::iter_json_array::<VTData, _>(reader).filter_map(|x| x.ok()) {
            if sender.send(element).is_err() {
                break;
            }
        }

        Ok(())
    })
    .await
}
