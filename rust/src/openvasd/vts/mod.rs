use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::BufReader;
use std::sync::RwLock;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use greenbone_scanner_framework::{GetVTsError, StreamResult};
use scannerlib::Promise;
use scannerlib::feed::{HashSumFileItem, HashSumNameLoader, check_signature};
use scannerlib::nasl::syntax::Loader;
use scannerlib::notus::advisory_loader;
use scannerlib::{
    models::{FeedState, FeedType, VTData},
    notus::advisories::VulnerabilityData,
    utils::scanner_types::ScannerType,
};
use walkdir::WalkDir;

use crate::config::Config;
pub mod orchestrator;
pub mod redis;
pub use crate::container_image_scanner::endpoints::vts::VTEndpoints as Endpoints;
use crate::database::sqlite::DataBase;
use crate::json_stream;
use crate::vts::orchestrator::WorkerError;
//use crate::vts::sql::SqlPluginStorage;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Contains the hash values of the sha256sums for specific feeds
pub struct FeedHash {
    pub hash: String,
    pub path: PathBuf,
    pub typus: FeedType,
}

pub type FeedHashes = (String, String);

fn sumfile_hash<S>(path: S) -> Result<String, scannerlib::feed::VerifyError>
where
    S: AsRef<Path> + Clone + std::fmt::Debug + Sync + Send,
{
    let loader = Loader::from_feed_path(path);
    let verifier = scannerlib::feed::HashSumNameLoader::sha256(&loader)?;
    verifier.sumfile_hash()
}

pub trait Plugin: serde::Serialize {
    fn oid(&self) -> &str;
    fn advisory(&self) -> Option<&VulnerabilityData>;
    fn vulnerability_test(&self) -> Option<&VTData>;
    fn hashsum(&self) -> &str;
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

    fn hashsum(&self) -> &str {
        // This should not be called, as we only need this for
        // storage of the hashsum in redis, where `VTData` is
        // not directly used as a `Plugin`, but instead we use
        // `VTDataMessage`
        unimplemented!()
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

    fn hashsum(&self) -> &str {
        ""
    }
}

fn error_vts_error<T>(error: T) -> GetVTsError
where
    T: std::error::Error + Sync + Send + 'static,
{
    GetVTsError::External(Box::new(error))
}

pub trait PluginFetcher {
    fn get_oids(&self) -> StreamResult<String, WorkerError>;

    fn get_vts(&self) -> StreamResult<VTData, WorkerError>;
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
    pool: DataBase,
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
            let fetcher = crate::database::sqlite::vts::SqlPluginStorage::from(pool.clone());
            let worker = crate::database::sqlite::vts::FeedSynchronizer::new(pool, config);
            _init(config, fetcher, worker, snapshot).await
        }
        ScannerType::Lambda => panic!("Invalid Scanner type"),
    }
}

pub trait PluginStorer {
    fn store_hash(&self, hash: &FeedHash) -> Promise<Result<(), WorkerError>>;
    fn store_plugin<T>(&self, hash: &FeedHash, plugin: T) -> Promise<Result<(), WorkerError>>
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

pub async fn synchronize_feed<T>(
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
            synchronize_plugins(ps, feed_hash.path, feed_hash.hash, signature_check).await?
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
        let loader = Loader::from_feed_path(&path);
        let advisories_files =
            advisory_loader(signature_check, &loader).map_err(error_vts_error)?;
        for result in advisories_files {
            match result {
                Ok(x) => {
                    for adv in x.advisories.advisories {
                        let data = VulnerabilityData {
                            adv,
                            family: x.advisories.family.clone(),
                            filename: x.filename.to_owned(),
                        };

                        if sender.send(data).is_err() {
                            break;
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "Unable to load advisories_file. Skipping.")
                }
            };
        }
        Ok(())
    })
    .await
}

async fn synchronize_plugins<T>(
    ps: &T,
    mut path: PathBuf,
    new_hash: String,
    signature_check: bool,
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
    let dir_path = path.clone();
    let mut sumsfile = HashMap::new();
    let loader = Loader::from_feed_path(&dir_path);
    if path.is_dir() {
        if signature_check {
            // perform the signature check, and verify the vt-metadata json file
            check_signature(&dir_path)?;
            let mut hashsumloader = HashSumNameLoader::sha256(&loader)?;
            while let Some(Ok(item)) = hashsumloader.next() {
                sumsfile.insert(item.file_name.clone(), item);
            }

            if let Some(jsonfile) = sumsfile.get("vt-metadata.json") {
                jsonfile.verify()?;
            }
        };

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
        // Load the hash256 sums and file names from the hash256sums file,
        // which was already verified (signature check)
        let mut sumsfile = HashMap::new();
        let loader = Loader::from_feed_path(&dir_path);

        if signature_check {
            check_signature(&dir_path)?;
            let mut hashsumloader = HashSumNameLoader::sha256(&loader)?;
            while let Some(Ok(item)) = hashsumloader.next() {
                sumsfile.insert(item.file_name.clone(), item);
            }
        }
        // .inc files are feed *includes* (NASL libraries), not VTs: they are
        // not listed in the vt-metadata json and carry no OID. We still want to
        // integrity-check them, but they must NOT be sent to the VT storage.
        // Previously each .inc was stored as a VTData with a shared placeholder
        // oid ("fake_oid"); with more than one .inc file that collides on the
        // unique `oid` key and aborts the whole NASL feed synchronization with
        // `UNIQUE constraint failed: plugins.oid`, leaving openvasd with no
        // runnable VTs. Verify the integrity of each .inc file in place instead.
        // The check only applies when signature verification is enabled (there
        // is nothing in the sums file to verify against otherwise).
        // TODO: improve the signature check for the whole feed.
        if signature_check {
            let target_ext = OsStr::new("inc");
            let inc_files = WalkDir::new(&dir_path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_file())
                .map(|entry| entry.into_path())
                .filter(|path| path.extension() == Some(target_ext))
                .collect::<Vec<_>>();
            for element in inc_files.iter() {
                let filename = element
                    .strip_prefix(&dir_path)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                if let Err(e) = verify_signature(&sumsfile, &filename) {
                    tracing::warn!(e);
                }
            }
        }

        // for nasl files we do the same, but iteration is done over json objects in
        // the vt-metadata.json
        let file = std::fs::File::open(&path).map_err(|_| not_found())?;
        let reader = BufReader::new(file);
        for element in json_stream::iter_json_array::<VTData, _>(reader).filter_map(|x| x.ok()) {
            if let Err(e) = verify_signature_and_send(&sender, &sumsfile, element, signature_check)
            {
                tracing::warn!(e);
            }
        }

        Ok(())
    })
    .await
}

// Sends a VTdatamessage struct to be loaded
/// Verify a feed file's hashsum against the (already signature-verified)
/// sha256sums file, returning its hashsum on success. Used both to integrity-
/// check feed includes (.inc files, which are not stored as VTs) and as the
/// verification step before sending a VT to storage.
fn verify_signature(
    sumsfile: &HashMap<String, HashSumFileItem<'_>>,
    filename: &str,
) -> Result<String, String> {
    let Some(checker) = sumsfile.get(filename) else {
        return Err(format!("File not present in sumsfile: {filename:?}"));
    };
    checker
        .verify()
        .map_err(|e| format!("Wrong hashsum for file: {e:?}"))?;
    Ok(checker.get_hashsum())
}

fn verify_signature_and_send(
    sender: &std::sync::mpsc::Sender<VTDataMessage>,
    sumsfile: &HashMap<String, HashSumFileItem<'_>>,
    item: VTData,
    signature_check: bool,
) -> Result<(), String> {
    let hashsum = if signature_check {
        verify_signature(sumsfile, &item.filename)?
    } else {
        "".into()
    };
    sender
        .send(VTDataMessage { item, hashsum })
        .map_err(|e| e.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct VTDataMessage {
    item: VTData,
    hashsum: String,
}

impl Plugin for VTDataMessage {
    fn oid(&self) -> &str {
        self.item.oid()
    }

    fn advisory(&self) -> Option<&VulnerabilityData> {
        self.item.advisory()
    }

    fn vulnerability_test(&self) -> Option<&VTData> {
        Some(&self.item)
    }

    fn hashsum(&self) -> &str {
        &self.hashsum
    }
}
