mod benchy;
pub mod config;
use std::sync::{Arc, RwLock};

pub use config::Config;
use greenbone_scanner_framework::{entry::Prefixed, models::FeedState};
use scheduling::Scheduler;
use sqlx::migrate::Migrator;
mod detection;
pub mod endpoints;
mod image;
mod messages;
mod notus;
mod scheduling;
pub(crate) use scannerlib::{ExternalError, PromiseRef, Streamer};

static MIGRATOR: Migrator = sqlx::migrate!("./src/openvasd/container_image_scanner/migrations");

use endpoints::scans::Scans;
//TODO: move endpoints to openvasd?
use endpoints::vts::VTEndpoints;

use scannerlib::notus::Notus;

use crate::{
    container_image_scanner::scheduling::db::DataBase, database::sqlite::vts::SqlPluginStorage,
};

pub async fn init(
    vt_pool: DataBase,
    feed_state: Arc<RwLock<FeedState>>,
    products: Arc<tokio::sync::RwLock<Notus>>,
    config: Config,
) -> Result<(Scans, VTEndpoints), Box<dyn std::error::Error + Send + Sync>> {
    let pool = config
        .database
        .create_pool("container-image-scanner")
        .await?;
    MIGRATOR.run(&pool).await?;

    let scheduler = Scheduler::init(config.into(), pool.clone(), products);
    tokio::spawn(scheduler.run());

    let scan = Scans { pool };
    let vts = VTEndpoints::new(
        SqlPluginStorage::from(vt_pool),
        feed_state,
        Some(scan.prefix()),
    );
    Ok((scan, vts))
}
