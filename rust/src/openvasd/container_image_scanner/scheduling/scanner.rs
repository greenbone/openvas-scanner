use std::sync::Arc;

use futures::{StreamExt, TryFutureExt};
use greenbone_scanner_framework::models;
use sqlx::{Sqlite, SqlitePool};
use tokio::sync::RwLock;

use crate::container_image_scanner::{
    Config, ExternalError,
    benchy::{self, BenchType, Benched, Measured},
    detection::{self, OperatingSystem},
    image::{
        Image, ImageParseError, Registry, RegistryError,
        extractor::{self, Extractor, Locator},
        packages::ToNotus,
    },
    messages::{self, CustomerMessage},
    notus,
};
use scannerlib::notus::{HashsumProductLoader, Notus};

#[derive(Debug, thiserror::Error)]
pub enum ScannerArchImageError {
    #[error("Unable to detect operating-system: {0}")]
    NoOS(#[from] ExternalError),
    #[error("Unable check vulnerabilities: {0}")]
    Notus(#[from] notus::Error),
    #[error("A DB error occurred: {0}")]
    StoreResults(#[from] sqlx::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("An error occurred while handling a image: {0}")]
    Image(#[from] ScannerArchImageError),

    #[error("Unable to extract image")]
    Extractor(#[from] extractor::ExtractorError),

    #[error("Unable to parse: `{0}`. Scan failed because of incorrect user input.")]
    ImageParseError(#[from] ImageParseError),

    #[error("Unable to scan: {0}")]
    RegistryError(#[from] RegistryError),
}

impl ScannerError {
    pub fn can_retry(&self) -> bool {
        match self {
            Self::RegistryError(r) => r.can_retry(),
            _ => false,
        }
    }
}

#[derive(Debug, Default)]
struct ImageResults {
    os: Option<OperatingSystem>,
    packages: Vec<String>,
    results: Vec<models::Result>,
}

impl ImageResults {
    fn no_packages(os: OperatingSystem) -> Self {
        let os = Some(os);
        Self {
            os,
            ..Default::default()
        }
    }

    fn no_os() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn results(os: OperatingSystem, packages: Vec<String>, results: Vec<models::Result>) -> Self {
        let os = Some(os);
        Self {
            os,
            packages,
            results,
        }
    }
}

impl Measured<ImageResults> {
    async fn store_log_messages(
        self,
        pool: &sqlx::Pool<Sqlite>,
        id: &str,
        image: &str,
        architecture: &str,
    ) -> Result<(), ScannerArchImageError> {
        let (scan_duration, result) = self.unpack();
        tracing::debug!(
            architecture,
            results = result.results.len(),
            packages = result.packages.len(),
            "Finished"
        );
        let mut messages = result.results;
        let message = |msg| CustomerMessage::log(Some(image), msg, None).into();

        let layer_timings = Benched::retrieve(pool, id, image).await;
        let (image_extraction, image_download) =
            layer_timings
                .iter()
                .fold((0, 0), |(ie, id), x| match x.kind() {
                    BenchType::Download => (ie, id + x.micro_seconds()),
                    BenchType::Extraction => (ie + x.micro_seconds(), id),
                    // usually not stored in the DB and if so ignored
                    BenchType::Scan | BenchType::All => (ie, id),
                });
        let scan_timings = [
            Benched::scan(&scan_duration),
            Benched::new(None, BenchType::Extraction, image_extraction),
            Benched::new(None, BenchType::Download, image_download),
            Benched::new(
                None,
                BenchType::All,
                image_download + image_extraction + scan_duration.as_micros(),
            ),
        ];
        scan_timings.iter().for_each(|x| {
            messages.push(message(x.msg()));
        });

        let msg = if result.os.is_none() {
            "No operating system information found.".to_string()
        } else {
            format!(
                "architecture({}), os({}), packages({})",
                architecture,
                result.os.unwrap(),
                result.packages.len(),
            )
        };
        messages.push(message(msg));

        messages::store(pool, id, &messages).await;

        Ok(())
    }
}

async fn scan_arch_image<L, T>(
    products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    locator: &L,
    image: String,
) -> Result<ImageResults, ScannerArchImageError>
where
    L: Locator + Send + Sync,
    T: ToNotus,
{
    use detection::OperatingSystemDetectionError as OSDE;
    match detection::operating_system(locator).await {
        Ok(os) => {
            let packages = T::packages(locator).await;

            let results = if packages.is_empty() {
                // This can also happen if a container image does not have a package DB anymore (e.g. the
                // rpm db did get deleted on purpose) hence we treat it as an INFO not as an error.
                ImageResults::no_packages(os)
            } else {
                let results = notus::vulnerabilities(
                    products,
                    locator.architecture(),
                    image.clone(),
                    &os,
                    packages.clone(),
                )
                .await?;
                ImageResults::results(os, packages, results)
            };

            Ok(results)
        }
        Err(OSDE::NotFound | OSDE::Unknown) => Ok(ImageResults::no_os()),
        Err(e) => Err(ScannerArchImageError::NoOS(e.into())),
    }
}

async fn download_and_extract_image<'a, E, R>(
    config: Arc<Config>,
    registry: &'a super::InitializedRegistry<'a, R>,
    image: Image,
) -> Result<(E, Vec<Benched>), ScannerError>
where
    E: Extractor + Send + Sync,
    R: Registry + Send + Sync,
{
    let mut extractor = E::initialize(config.clone(), registry.id.clone()).await?;
    let mut layers = registry.registry.pull_image(image.clone());
    let mut results = Vec::new();

    tracing::debug!("downloading");
    while let Some(packet) = layers.next().await {
        let layer = packet?;
        let lindex = layer.index;
        results.push(Benched::download(lindex, &layer.download_time));

        tracing::debug!(
            download_time_ms = layer.download_time.as_millis(),
            layer = lindex,
            "downloaded"
        );
        let duration = extractor.extract(layer).await?;
        results.push(Benched::extraction(lindex, &duration));

        tracing::debug!(
            extraction_ms = duration.as_millis(),
            layer = lindex,
            "extracted"
        );
    }
    tracing::debug!("downloaded");
    Ok((extractor, results))
}

async fn retry_download_and_extract_image<'a, E, R>(
    config: Arc<Config>,
    pool: &SqlitePool,
    registry: &'a super::InitializedRegistry<'a, R>,
    image: Image,
) -> Result<E, ScannerError>
where
    E: Extractor + Send + Sync,
    R: Registry + Send + Sync,
{
    // alternatively set back to pending and store retry amount alongside the image
    let mut retries = config.image.scanning_retries;
    loop {
        match download_and_extract_image(config.clone(), registry, image.clone()).await {
            Ok((ex, benched)) => {
                for b in benched {
                    b.store(pool, registry.id.id(), registry.id.image()).await;
                }
                return Ok(ex);
            }
            Err(error) if error.can_retry() && retries > 0 => {
                retries -= 1;
                tracing::info!(%error, retries, "Retrying.");
                tokio::time::sleep(config.image.retry_timeout).await;
            }
            Err(error) => return Err(error),
        }
    }
}

pub async fn scan_image<'a, E, R, T>(
    config: Arc<Config>,
    pool: sqlx::Pool<Sqlite>,
    products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    registry: &'a super::InitializedRegistry<'a, R>,
) -> Result<(), Vec<ScannerError>>
where
    E: Extractor + Send + Sync,
    R: Registry + Send + Sync,
    T: ToNotus,
{
    let image: Image = registry
        .id
        .image()
        .parse()
        .map_err(|e| vec![ScannerError::from(e)])?;

    let locator_per_arch = retry_download_and_extract_image::<E, _>(config, &pool, registry, image)
        .await
        .map_err(|e| vec![e])?
        .locator()
        .await;
    let mut errors = Vec::with_capacity(locator_per_arch.len());
    for locator in locator_per_arch.iter() {
        let measured = benchy::measure_result(scan_arch_image::<_, T>(
            products.clone(),
            locator,
            registry.id.image.to_owned(),
        ));

        if let Err(e) = measured
            .and_then(|results| {
                results.store_log_messages(
                    &pool,
                    registry.id.id(),
                    registry.id.image(),
                    locator.architecture(),
                )
            })
            .await
        {
            errors.push(e.into());
        };
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
