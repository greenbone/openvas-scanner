use std::{marker::PhantomData, sync::Arc, time::Duration};

use container_image_scanner::{
    ExternalError, ParsePreferences,
    config::Config,
    image,
    image::{Credential, Image, ImageID, packages::ToNotus},
};
use futures::StreamExt;
use greenbone_scanner_framework::models;
use tokio::{
    sync::{
        Mutex, RwLock,
        mpsc::{Receiver, Sender},
    },
    task::JoinSet,
    time,
};
use tracing::{debug, instrument, warn};

use crate::{
    container_image_scanner::{
        self,
        image::{ImageParseError, ImageState},
        messages::CustomerMessage,
        scheduling::{
            db::{DataBase, images::DBImages, preferences::DBPreferences, scan::DBScan},
            scanner::{ScannerArchImageError, ScannerError},
        },
    },
    database::dao::{DAOError, Execute, Fetch, RetryExec, StreamFetch},
};
use scannerlib::notus::{HashsumProductLoader, Notus, NotusError};

// TODO: refactor, this got a bit too messy
pub mod db;
mod scanner;

pub async fn image_failed(pool: &DataBase, id: &ImageID) {
    if let Err(error) = DBImages::new(pool, (id, ImageState::Failed))
        .retry_exec()
        .await
    {
        tracing::warn!(%error, "Unable to set status to failed.")
    }
}

pub async fn image_success(pool: &DataBase, id: &ImageID) {
    if let Err(error) = DBImages::new(pool, (id, ImageState::Succeeded))
        .retry_exec()
        .await
    {
        tracing::warn!(%error, "Unable to set status to succeeded.")
    }
}

#[derive(Debug, Clone)]
pub struct ProcessingImage {
    pub id: String,
    pub image: Vec<Result<Image, ImageParseError>>,
    pub credentials: Option<Credential>,
}
#[derive(Debug)]
pub struct Message {
    pub id: String,
    pub action: models::Action,
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
    pool: DataBase,
    config: Arc<Config>,
    registry: PhantomData<Registry>,
    extractor: PhantomData<Extractor>,
    products: Arc<RwLock<Notus<HashsumProductLoader>>>,
}

impl<Registry, Extractor> Scheduler<Registry, Extractor> {
    fn new(
        config: Arc<Config>,
        receiver: Receiver<Message>,
        pool: DataBase,
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
        pool: DataBase,
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

use crate::container_image_scanner::image::RegistryError;

impl<R, E> Scheduler<R, E>
where
    R: container_image_scanner::image::Registry + Send + Sync,
    E: container_image_scanner::image::extractor::Extractor + Send + Sync,
{
    #[cfg(test)]
    pub fn pool(&self) -> DataBase {
        self.pool.clone()
    }

    #[cfg(test)]
    pub fn receiver(&mut self) -> &mut Receiver<Message> {
        &mut self.receiver
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
        pool: &DataBase,
        id: &str,
        credentials: Option<Credential>,
    ) -> Result<R, RegistryError> {
        let result = DBPreferences::new(pool, id.to_owned())
            .stream_fetch()
            .filter_map(|x| async move { x.ok() });
        let prefs = image::RegistrySetting::parse_preferences(result).await;
        R::initialize(credentials, prefs)
    }

    #[instrument(skip_all, fields(id = pimage.id))]
    async fn resolve_all_images(
        pool: DataBase,
        pimage: &ProcessingImage,
    ) -> Result<Vec<Result<Image, RegistryError>>, ExternalError> {
        let registry = Self::registry(&pool, &pimage.id, pimage.credentials.clone()).await?;

        let mut result = Vec::with_capacity(100);
        for image in pimage
            .image
            .iter()
            //TODO: refactor ResolveRequested this is just needlessly annoying
            .map(|x| x.clone().map_err(|_| RegistryError::no_repository()))
        {
            match image {
                Err(e) => result.push(Err(e)),
                Ok(x) => {
                    let extended_images = registry.resolve_image(x).await;
                    result.extend(extended_images)
                }
            }
        }
        drop(registry);
        tracing::debug!(id = pimage.id, images = result.len(), "Resolved");
        Ok(result)
    }

    #[instrument(skip_all, fields(id=image.id))]
    pub(crate) async fn resolve_and_store_images(
        pool: DataBase,
        image: ProcessingImage,
    ) -> Result<(), DAOError> {
        let id = &image.id as &str;
        DBScan::new(&pool, (id, models::Phase::Running))
            .retry_exec()
            .await?;
        tracing::debug!("Set to running.");
        let images = match Self::resolve_all_images(pool.clone(), &image).await {
            Err(e) => {
                warn!(error=%e, ids=?image.id, "Unable to initialize registry. Setting scan to failed.");
                return DBScan::new(&pool, (id, models::Phase::Failed))
                    .retry_exec()
                    .await;
            }
            Ok(x) => x,
        };
        DBScan::new(&pool, (id, &images as &[_])).retry_exec().await
    }

    pub(crate) async fn start_scans<T>(
        config: Arc<Config>,
        // TODO: is that really necessary?
        conn: Arc<Mutex<DataBase>>,
        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    ) where
        T: ToNotus,
    {
        tracing::debug!("checking for requested and scanning");
        let pool = conn.lock().await;
        let requested = match DBImages::new(&pool, config.max_scans).fetch().await {
            Ok(r) => r,
            Err(error) => {
                tracing::warn!(%error, "Unable to fetch images from the DB");
                return;
            }
        };
        let catalog_pool = pool.clone();
        for r in requested {
            if let Err(error) = Self::resolve_and_store_images(catalog_pool.clone(), r).await {
                tracing::warn!(%error, "Unable to set image status after fetching the images");
            }
        }

        let scan_pool = pool.clone();
        Self::scan_images::<T>(config, scan_pool, products).await;

        if let Err(error) = DBScan::new(&pool, models::Phase::Succeeded).exec().await {
            tracing::warn!(%error, "Unable to set scans to finished");
        }
    }

    #[instrument(skip_all, fields(id=id.id(), image=id.image()))]
    async fn scan_image<T>(
        config: Arc<Config>,
        pool: DataBase,
        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
        id: &ImageID,
        credentials: Option<Credential>,
    ) where
        T: ToNotus,
    {
        match Self::registry(&pool, id.id(), credentials).await {
            Ok(registry) => {
                let registry = InitializedRegistry { id, registry };

                match scanner::scan_image::<E, R, T>(
                    config.clone(),
                    pool.clone(),
                    products,
                    &registry,
                )
                .await
                {
                    Ok(_) => {
                        image_success(&pool, id).await;
                    }
                    Err(err) => {
                        // Notus error should not set a scan to failed
                        if err
                            .iter()
                            .filter_map(|x| match x {
                                ScannerError::Image(ScannerArchImageError::Notus(
                                    NotusError::UnknownProduct(_),
                                )) => None,
                                ScannerError::Image(_)
                                | ScannerError::Extractor(_)
                                | ScannerError::ImageParseError(_)
                                | ScannerError::RegistryError(_) => Some(true),
                            })
                            .any(|x| x)
                        {
                            image_failed(&pool, id).await;
                        } else {
                            image_success(&pool, id).await;
                        }
                        for e in err {
                            if let ScannerError::Image(ScannerArchImageError::Notus(
                                NotusError::UnknownProduct(product),
                            )) = &e
                            {
                                tracing::info!(
                                    product,
                                    "Not found in notus products. This is not considered a scan failure reason."
                                );
                            } else {
                                tracing::warn!(error=%e, "This is considered a scan failure reason.");
                            }
                            CustomerMessage::error(Some(id.image.clone()), format!("{e}"), None)
                                .store(&pool, id.id())
                                .await;
                        }
                    }
                }
                // Contains http client with inner buffers so we don't want to it to potentially
                // linger around
                drop(registry);
            }

            Err(error) => tracing::warn!(%error, "Unable to initiate registry"),
        }
    }

    async fn scan_images<T>(
        config: Arc<Config>,
        pool: DataBase,
        products: Arc<RwLock<Notus<HashsumProductLoader>>>,
    ) where
        T: ToNotus,
    {
        let scans = match DBImages::new(
            &pool,
            (config.image_max_scanning(), config.image_batch_size()),
        )
        .exec()
        .await
        {
            Ok(x) => x,
            Err(error) => {
                tracing::warn!(%error, "Unable to set images to running.");
                return;
            }
        };

        let mut js = JoinSet::new();
        for (id, credentials) in scans {
            let pool = pool.clone();
            let config = config.clone();
            let products = products.clone();
            js.spawn(async move {
                Self::scan_image::<T>(config, pool.clone(), products, &id, credentials).await;
            });
        }
        js.join_all().await;
    }

    pub async fn run<T>(mut self)
    where
        T: ToNotus,
    {
        // we use the batch_size as the check_interval this allows customers to express:
        // 10:2 for a 1000mb/s
        // 25:2 for a 2500mb/s
        // 50:2 for a 5000mb/s
        // 100:2 for a 10000mb/s
        // and so on.
        let check_interval = Duration::from_secs(if self.config.image.batch_size == 0 {
            1
        } else {
            self.config.image.batch_size as u64
        });
        let mut interval = time::interval(check_interval);
        let config = self.config.clone();

        let pool = self.pool.clone();
        // ehww....
        let conn = pool.clone();
        let conn = Arc::new(Mutex::new(conn));
        loop {
            tokio::select! {
                Some(msg) = self.receiver.recv() => {
                let pool = self.pool.clone();

                tokio::spawn(async move {
                    let id = msg.id.clone();

                    if let Err(e) = DBScan::new(&pool, (msg.id, msg.action))
                        .retry_exec()
                        .await {
                        warn!(error=%e, id, "Unable to handle message");
                    }
                });
                }

                _ = interval.tick() => {
                let products = self.products.clone();
                let config = config.clone();
                let conn = conn.clone();

                tokio::spawn(async move {
                    Self::start_scans::<T>(config, conn, products).await
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
