use std::sync::RwLock;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use greenbone_scanner_framework::GetVTsError;
use scannerlib::{
    models::{FeedState, FeedType, VTData},
    notus::advisories::VulnerabilityData,
};
use sqlx::SqlitePool;

use crate::config::Config;
pub mod orchestrator;
pub mod sql;
pub use crate::container_image_scanner::endpoints::vts::VTEndpoints as Endpoints;

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
) -> (orchestrator::Communicator, Endpoints) {
    let endpoints = Endpoints::new(pool.clone(), snapshot.clone(), None);
    let worker = sql::FeedSynchronizer::new(pool, config);

    let communicator =
        orchestrator::Orchestrator::init(config.feed.check_interval, snapshot, worker).await;
    (communicator, endpoints)
}
