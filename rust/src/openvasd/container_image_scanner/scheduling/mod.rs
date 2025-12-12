use std::{marker::PhantomData, sync::Arc, time::Duration};

use container_image_scanner::{
    ExternalError, ParsePreferences,
    config::Config,
    image,
    image::{Credential, Image, ImageID, packages::ToNotus},
};
use db::{ProcessingImage, RequestedScans};
use futures::future::join_all;
use greenbone_scanner_framework::models;
use scanner::ScannerError;
use sqlx::{Sqlite, SqlitePool};
use tokio::{
    sync::{
        RwLock,
        mpsc::{Receiver, Sender},
    },
    time,
};
use tracing::{debug, warn};

use crate::container_image_scanner;
use scannerlib::{
    models::ResultType,
    notus::{HashsumProductLoader, Notus},
};

mod db;
mod scanner;

#[derive(Debug)]
pub struct Message {
    id: String,
    action: models::Action,
}

impl Message {
    pub fn new(id: String, action: models::Action) -> Self {
        Self { id, action }
    }
}

/// Scheduler is responsible to start, stop and storing results of scans.
///
/// It retrieves commands usually by the endpoint handler to either start or stop a scan.
/// It then sets the status of that scan to queued and regularly verifies if a scan can be started
/// when the scan is finished it also sets the status to either succeed or failed.
pub struct Scheduler<Registry, Extractor> {
    receiver: Receiver<Message>,
    pool: SqlitePool,
    config: Arc<Config>,
    registry: PhantomData<Registry>,
    extractor: PhantomData<Extractor>,
    products: Arc<RwLock<Notus<HashsumProductLoader>>>,
}

impl<Registry, Extractor> Scheduler<Registry, Extractor> {
    fn new(
        config: Arc<Config>,
        receiver: Receiver<Message>,
        pool: sqlx::Pool<Sqlite>,
        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    ) -> Self {
        Scheduler {
            receiver,
            pool,
            config,
            registry: PhantomData,
            extractor: PhantomData,
            products,
        }
    }

    pub fn init(
        config: Arc<Config>,
        pool: sqlx::Pool<Sqlite>,
        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    ) -> (Sender<Message>, Scheduler<Registry, Extractor>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(10);
        (sender, Self::new(config, receiver, pool, products))
    }
}

//TODO delete
struct InitializedRegistry<'a, Registry> {
    id: &'a ImageID,
    registry: Registry,
}

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
enum ScanImageError {
    ScannerError(#[from] ScannerError),
    RegistryErrir(#[from] ExternalError),
}

impl<R, E> Scheduler<R, E>
where
    R: container_image_scanner::image::Registry + Send + Sync,
    E: container_image_scanner::image::extractor::Extractor + Send + Sync,
{
    #[cfg(test)]
    pub fn pool(&self) -> sqlx::Pool<Sqlite> {
        self.pool.clone()
    }

    #[cfg(test)]
    pub fn config(&self) -> Arc<Config> {
        self.config.clone()
    }

    #[cfg(test)]
    pub fn products(&self) -> Arc<RwLock<Notus<HashsumProductLoader>>> {
        self.products.clone()
    }

    async fn registry(
        pool: &sqlx::Pool<Sqlite>,
        id: &str,
        credentials: Option<Credential>,
    ) -> Result<R, ExternalError> {
        let result = db::preferences(pool, id);
        let prefs = image::RegistrySetting::parse_preferences(result).await;
        R::initialize(credentials, prefs)
    }

    async fn resolve_all_images(
        pool: sqlx::Pool<Sqlite>,
        image: &ProcessingImage,
    ) -> Result<Vec<Result<Image, ExternalError>>, ExternalError> {
        let registry = Self::registry(&pool, &image.id, image.credentials.clone()).await?;

        let mut result = Vec::with_capacity(100);
        for image in image.image.iter().map(|x| x.clone().map_err(|e| e.into())) {
            match image {
                Err(e) => result.push(Err(e)),
                Ok(x) => {
                    //let span = tracing::span!(tracing::Level::TRACE, "resolve_all_images", %x,);
                    //let _enter = span.enter();
                    //
                    // FIXME: verify the result for errors and set the image to failed there is an
                    // error otherwise it will try to resolve_all_images endlessly for that scan.
                    let extended_images = registry.resolve_image(x).await;
                    result.extend(extended_images)
                }
            }
        }

        Ok(result)
    }

    pub(crate) async fn resolve_and_store_images(
        image: ProcessingImage,
        pool: sqlx::Pool<Sqlite>,
    ) -> Result<(), sqlx::Error> {
        db::set_scan_to_running(&pool, &image.id).await?;
        let images = match Self::resolve_all_images(pool.clone(), &image).await {
            Err(e) => {
                warn!(error=%e, ids=?image.id, "Unable to initialize registry. Setting scan to failed.");
                return db::set_scan_to_failed(&pool, &image.id).await;
            }
            Ok(x) => x,
        };

        db::set_scan_images(&pool, &image.id, images).await
    }

    pub(crate) async fn start_scans<T>(
        config: Arc<Config>,
        pool: sqlx::Pool<Sqlite>,
        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    ) where
        T: ToNotus,
    {
        let max_concurrent_scans = 2;

        let requested = RequestedScans::fetch(&pool, max_concurrent_scans).await;
        for r in requested {
            if let Err(error) = Self::resolve_and_store_images(r, pool.clone()).await {
                tracing::warn!(%error, "Unable to set image status after fetching the images");
            }
        }
        Self::scan_images::<T>(config, pool.clone(), products).await;
        if let Err(error) = db::set_scans_to_finished(&pool).await {
            tracing::warn!(%error, "Unable to set scans to finished");
        }
    }

    async fn set_images_to_scanning(
        config: Arc<Config>,
        pool: &sqlx::Pool<Sqlite>,
    ) -> Result<Vec<(ImageID, Option<Credential>)>, sqlx::error::Error> {
        let mut tx = pool.begin().await?;
        let scan_limit = match config.image_max_scanning() {
            0 => -1,
            max => {
                let max = max as i64;
                let current_scanning: (i64,) =
                    sqlx::query_as("SELECT COUNT(*) FROM images WHERE status = 'scanning'")
                        .fetch_one(&mut *tx)
                        .await?;
                if current_scanning.0 >= max {
                    0
                } else {
                    max - current_scanning.0
                }
            }
        };
        if scan_limit == 0 {
            return Ok(vec![]);
        }
        let limit = match config.image_batch_size() {
            0 => scan_limit,
            max if max > scan_limit as usize => scan_limit, // -1 will be usize::MAX
            max => max as i64,
        };

        let rows = sqlx::query(
            r#"
    SELECT i.id, i.image, c.username, c.password
    FROM images i
    LEFT JOIN credentials c ON i.id = c.id
    WHERE i.status = 'pending'
    LIMIT ?
    "#,
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let credentials = db::row_to_credential(&row);
            let id: ImageID = row.into();

            sqlx::query(
                r#"
        UPDATE images
        SET status = 'scanning'
        WHERE id = ? AND image = ?
        "#,
            )
            .bind(id.id())
            .bind(id.image())
            .execute(&mut *tx)
            .await?;
            result.push((id, credentials));
        }
        tx.commit().await?;

        Ok(result)
    }

    async fn scan_image<T>(
        config: Arc<Config>,
        pool: sqlx::Pool<Sqlite>,
        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
        id: &ImageID,
        credentials: Option<Credential>,
    ) -> Result<(), ScanImageError>
    where
        T: ToNotus,
    {
        let registry = Self::registry(&pool, id.id(), credentials)
            .await
            .map_err(ScanImageError::RegistryErrir)?;

        let registry = InitializedRegistry { id, registry };

        scanner::scan_image::<E, R, T>(config.clone(), pool.clone(), products, &registry)
            .await
            .map_err(ScanImageError::ScannerError)
    }

    async fn scan_images<T>(
        config: Arc<Config>,
        pool: sqlx::Pool<Sqlite>,

        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    ) where
        T: ToNotus,
    {
        let scans = Self::set_images_to_scanning(config.clone(), &pool)
            .await
            .unwrap();
        let join_handler = scans
            .into_iter()
            .map(|(id, credentials)| {
                let pool = pool.clone();
                let config = config.clone();
                let products = products.clone();
                tokio::task::spawn(async move {
                    let result =
                        Self::scan_image::<T>(config, pool.clone(), products, &id, credentials)
                            .await;
                    match result {
                        Ok(_) => {
                            if let Err(e) = db::image_success(&pool, &id).await {
                                warn!(error = %e, ?id, "Unable to update scan hosts information.");
                            }
                        }
                        Err(err) => {
                            if let Err(e) = db::image_failed(&pool, &id).await {
                                warn!(error = %e, ?id, "Unable to update scan hosts information.");
                            }
                            match &err {
                                ScanImageError::ScannerError(
                                    //TODO: The name and design is misleading.
                                    scanner::ScannerError::NonInterrupting(items),
                                ) => {
                                    for e in items {
                                        warn!(error = %e, "Image failed.");
                                        db::internal_result(
                                            &pool,
                                            &id.id,
                                            ResultType::Error,
                                            Some(id.image.clone()),
                                            e.clone(),
                                        )
                                        .await;
                                    }
                                }
                                e => {
                                    db::internal_result(
                                        &pool,
                                        &id.id,
                                        ResultType::Error,
                                        Some(id.image.clone()),
                                        e.to_string(),
                                    )
                                    .await;
                                    warn!(error = %e, "Image failed");
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        join_all(join_handler).await;
    }

    pub(crate) async fn check_for_message(&mut self) -> Option<()> {
        let msg = self.receiver.recv().await?;
        if let Err(e) = db::on_message(&self.pool, &msg).await {
            warn!(error=%e, id=msg.id, "Unable to handle message");
        }
        Some(())
    }

    pub async fn run<T>(mut self, check_interval: Duration)
    where
        T: ToNotus,
    {
        let mut interval = time::interval(check_interval);
        let config = self.config.clone();
        let pool = self.pool.clone();
        loop {
            tokio::select! {
                Some(()) = self.check_for_message() => {

                let products = self.products.clone();
                let config = config.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    Self::start_scans::<T>(config, pool, products).await
                });

                }

                _ = interval.tick() => {

                let products = self.products.clone();
                let config = config.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    Self::start_scans::<T>(config, pool, products).await

                });

                }


                else => {
                    debug!("Channel closed, good bye");
                    break;
                }
            }
        }
    }
}
