mod benchy;
pub mod config;
use std::sync::Arc;

use crate::{credentials, crypt::ChaCha20Crypt};
pub use config::Config;
use futures::{Stream, StreamExt};
use image::{DockerRegistryV2, extractor::filtered_image, packages::AllTypes};
use scheduling::Scheduler;
use sqlx::migrate::Migrator;
mod detection;
pub mod endpoints;
mod image;
mod messages;
mod notus;
mod scheduling;
pub(crate) use scannerlib::{ExternalError, Promise, PromiseRef, Streamer};

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

use endpoints::scans::ScanState;
use scannerlib::notus::Notus;

pub(crate) fn config_to_crypt(config: &Config) -> ChaCha20Crypt {
    credentials::config_to_crypt(config.database.credential_key.as_deref())
}

pub async fn init(
    products: Arc<tokio::sync::RwLock<Notus>>,
    config: Config,
) -> Result<ScanState<ChaCha20Crypt>, Box<dyn std::error::Error + Send + Sync>> {
    let pool = config
        .database
        .create_pool("container-image-scanner")
        .await?;
    MIGRATOR.run(&pool).await?;

    let crypter = Arc::new(config_to_crypt(&config));
    let scheduler = Scheduler::<DockerRegistryV2, filtered_image::Extractor, ChaCha20Crypt>::init(
        config.into(),
        pool.clone(),
        crypter.clone(),
        products,
    )
    .await?;
    tokio::spawn(async move {
        scheduler.run::<AllTypes>().await;
    });

    let scan_state = ScanState { pool, crypter };
    Ok(scan_state)
}
