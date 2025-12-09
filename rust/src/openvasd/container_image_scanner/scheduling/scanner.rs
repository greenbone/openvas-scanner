use std::{fmt::Display, sync::Arc};

use futures::{StreamExt, TryFutureExt};
use greenbone_scanner_framework::models;
use sqlx::Sqlite;
use tokio::sync::RwLock;

use super::db;
use crate::container_image_scanner::{
    Config, ExternalError, detection,
    image::{
        Image, ImageParseError, Registry,
        extractor::{self, Extractor, ExtractorError, Locator},
        packages::ToNotus,
    },
    notus,
};
use scannerlib::{
    models::ResultType,
    notus::{HashsumProductLoader, Notus},
};

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

    #[error("Issues occurred, that may lead to inaccurate results.")]
    NonInterrupting(Vec<String>),
}

async fn scan_arch_image<L, T>(
    pool: &sqlx::Pool<Sqlite>,
    id: &str,
    products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    locator: &L,
    image: String,
) -> Result<Vec<models::Result>, ScannerArchImageError>
where
    L: Locator + Send + Sync,
    T: ToNotus,
{
    let os = detection::operating_system(locator).await?;
    let packages = T::packages(locator).await;
    db::internal_result(
        pool,
        id,
        ResultType::Log,
        Some(&image),
        format!(
            "architecture({}), os({os}), packages({})",
            locator.architecture(),
            packages.len()
        ),
    )
    .await;

    if packages.is_empty() {
        // This can also happen if a container image does not have a package DB anymore (e.g. the
        // rpm db did get deleted on purpose) hence we treat it as an INFO not as an error.
        tracing::info!(operating_system=?os, image, "No packages found.");
        return Ok(vec![]);
    }

    let results =
        notus::vulnerabilities(products, locator.architecture(), image, &os, packages).await?;
    Ok(results)
}
pub async fn scan_image<'a, E, R, T>(
    config: Arc<Config>,
    pool: sqlx::Pool<Sqlite>,
    products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    registry: &'a super::InitializedRegistry<'a, R>,
) -> Result<(), ScannerError>
where
    E: Extractor + Send + Sync,
    R: Registry + Send + Sync,
    T: ToNotus,
{
    let image: Image = registry.id.image().parse()?;
    let mut extractor = match E::initialize(config.clone(), registry.id.clone()).await {
        Ok(x) => x,
        Err(ExtractorError::Io(error)) => match error.kind() {
            std::io::ErrorKind::Other if error.to_string().contains("GZIP") => {
                db::internal_result(
                    &pool,
                    registry.id.id(),
                    ResultType::Error,
                    Some(registry.id.image()),
                    format!("GZIP is currently not supported: {error}"),
                )
                .await;
                return Ok(());
            }

            _ => return Err(ExtractorError::Io(error).into()),
        },
        Err(e) => return Err(e.into()),
    };
    let mut layers = registry.registry.pull_image(image);
    let mut warnings = Vec::new();
    let mut add_warning = |prefix: &dyn Display, error: &dyn Display| {
        warnings.push(format!(
            "{}:{}({prefix}): {error}",
            registry.id.id(),
            registry.id.image()
        ));
    };
    while let Some(packet) = layers.next().await {
        match packet {
            Ok(layer) => {
                let lindex = layer.index;
                match extractor.push(layer).await {
                    Ok(()) => {}
                    Err(x) => {
                        add_warning(&format!("Layer({lindex})"), &x);
                    }
                }
            }
            Err(e) => {
                add_warning(&"Packet", &e);
            }
        }
    }
    let locator_per_arch = extractor.extract().await;
    for locator in locator_per_arch.iter() {
        if let Err(e) = scan_arch_image::<_, T>(
            &pool,
            registry.id.id(),
            products.clone(),
            locator,
            registry.id.image.to_owned(),
        )
        .and_then(|results| {
            db::store_results(&pool, registry.id.id(), results).map_err(ScannerArchImageError::from)
        })
        .await
        {
            db::internal_result(
                &pool,
                registry.id.id(),
                ResultType::Error,
                Some(registry.id.image()),
                format!("{e}"),
            )
            .await;
            if !matches!(e, ScannerArchImageError::Notus(_)) {
                add_warning(&format!("Locator({})", locator.architecture()), &e);
            }
        };
    }
    if warnings.is_empty() {
        Ok(())
    } else {
        Err(ScannerError::NonInterrupting(warnings))
    }
}
