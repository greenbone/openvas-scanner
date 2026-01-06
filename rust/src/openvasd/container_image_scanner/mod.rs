mod benchy;
pub mod config;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

pub use config::Config;
use futures::{Stream, StreamExt};
use greenbone_scanner_framework::{entry::Prefixed, models::FeedState};
use image::{DockerRegistryV2, extractor::filtered_image, packages::AllTypes};
use scheduling::Scheduler;
use sqlx::migrate::Migrator;
mod detection;
pub mod endpoints;
mod image;
mod messages;
mod notus;
mod scheduling;
pub(crate) use scannerlib::{ExternalError, PinBoxFut, PinBoxFutRef, Streamer};

/// combines slices on compile time
#[macro_export]
macro_rules! concat_slices {
    ($slices:expr) => {{
        const fn flatten<const N: usize>(input: &[&[&'static str]]) -> [&'static str; N] {
            let mut out = [""; N];
            let mut i = 0;
            let mut idx = 0;
            while i < input.len() {
                let slice = input[i];
                let mut j = 0;
                while j < slice.len() {
                    out[idx] = slice[j];
                    j += 1;
                    idx += 1;
                }
                i += 1;
            }
            out
        }

        const fn total_len(slices: &[&[&str]]) -> usize {
            let mut total = 0;
            let mut i = 0;
            while i < slices.len() {
                total += slices[i].len();
                i += 1;
            }
            total
        }

        const FILES: &[&[&str]] = $slices;
        const LEN: usize = total_len(FILES);
        &flatten::<LEN>(FILES)
    }};
}

/// Parses preferences from (str, str) to an actual preferences.
///
/// Usually the preferences are coming from user input, are stored within preferences table and
/// then fetched and parsed for the actual system. See image::registry as an example.
trait ParsePreferences<T> {
    fn parse_preference_entry(key: &str, value: &str) -> Option<T>;

    async fn parse_preferences<Iter>(preferences: Iter) -> Vec<T>
    where
        Iter: Stream<Item = (String, String)>,
    {
        preferences
            .filter_map(
                |(k, v)| async move { Self::parse_preference_entry(k.as_ref(), v.as_ref()) },
            )
            .collect()
            .await
    }
}

static MIGRATOR: Migrator = sqlx::migrate!("./src/openvasd/container_image_scanner/migrations");

use endpoints::scans::Scans;
//TODO: move endpoints to openvasd?
use endpoints::vts::VTEndpoints;
use sqlx::SqlitePool;

use scannerlib::notus::{HashsumProductLoader, Notus};

use crate::vts::sql::SqlPluginStorage;
pub async fn init(
    vt_pool: SqlitePool,
    feed_state: Arc<RwLock<FeedState>>,
    products: Arc<tokio::sync::RwLock<Notus<HashsumProductLoader>>>,
    config: Config,
) -> Result<(Scans, VTEndpoints), Box<dyn std::error::Error + Send + Sync>> {
    let pool = config
        .database
        .create_pool("container-image-scanner")
        .await?;
    MIGRATOR.run(&pool).await?;

    let (sender, scheduler) = Scheduler::<DockerRegistryV2, filtered_image::Extractor>::init(
        config.into(),
        pool.clone(),
        products,
    );
    tokio::spawn(async move {
        scheduler.run::<AllTypes>(Duration::from_secs(10)).await;
    });

    let scan = Scans {
        pool,
        scheduling: sender,
    };
    let vts = VTEndpoints::new(
        SqlPluginStorage::from(vt_pool),
        feed_state,
        Some(scan.prefix()),
    );
    Ok((scan, vts))
}
