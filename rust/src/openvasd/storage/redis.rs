// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use scannerlib::models::{self, Scan, Status, VulnerabilityData};
use scannerlib::nasl::FSPluginLoader;
use scannerlib::storage::item::Nvt;
use scannerlib::storage::redis::{
    self, CacheDispatcher, RedisCtx, RedisGetNvt, RedisWrapper, FEEDUPDATE_SELECTOR,
    NOTUSUPDATE_SELECTOR,
};
use scannerlib::storage::{item::PerItemDispatcher, Dispatcher, Field};
use scannerlib::storage::{ContextKey, DefaultDispatcher, StorageError};
use scannerlib::{
    feed,
    notus::{AdvisoryLoader, HashsumAdvisoryLoader},
};
use tokio::{sync::RwLock, task::JoinSet};

use crate::{config::Config, controller::ClientHash, storage::FeedType};
use scannerlib::models::scanner::ScanResults;

use super::{
    AppendFetchResult, Error, FeedHash, FromConfigAndFeeds, NVTStorer, ProgressGetter,
    ScanIDClientMapper, ScanStorer,
};

pub struct Storage<T> {
    hash: RwLock<Vec<FeedHash>>,

    url: Arc<String>,
    underlying: T,
}

impl<T> Storage<T> {
    pub fn new(underlying: T, url: String, feed: Vec<FeedHash>) -> Storage<T> {
        Storage {
            hash: RwLock::new(feed),
            url: Arc::new(url),
            underlying,
        }
    }

    async fn update_advisories(url: Arc<String>, p: PathBuf) -> Result<(), Error> {
        let notus_feed_path = p;
        tokio::task::spawn_blocking(move || {
            tracing::debug!("starting notus feed update");
            let loader = FSPluginLoader::new(notus_feed_path);
            let advisories_files = HashsumAdvisoryLoader::new(loader.clone())?;

            let redis_cache: CacheDispatcher<RedisCtx> =
                CacheDispatcher::init(&url, NOTUSUPDATE_SELECTOR)?;
            let store = PerItemDispatcher::new(redis_cache);
            for filename in advisories_files.get_advisories()?.iter() {
                let advisories = advisories_files.load_advisory(filename)?;

                for adv in advisories.advisories {
                    let data = VulnerabilityData {
                        adv,
                        family: advisories.family.clone(),
                        filename: filename.to_owned(),
                    };
                    store.dispatch(
                        &Default::default(),
                        Field::NotusAdvisory(Box::new(Some(data))),
                    )?;
                }
            }
            store.dispatch(&Default::default(), Field::NotusAdvisory(Box::new(None)))?;
            tracing::debug!("finished notus feed update");
            Ok(())
        })
        .await
        .unwrap()
    }

    async fn update_nasl(
        url: Arc<String>,
        nasl_feed_path: PathBuf,
        current_feed: String,
    ) -> Result<(), Error> {
        tracing::debug!("starting nasl feed update");
        let oversion = "0.1";
        let loader = FSPluginLoader::new(nasl_feed_path);
        let verifier = feed::HashSumNameLoader::sha256(&loader)?;

        let redis_cache: CacheDispatcher<RedisCtx> =
            redis::CacheDispatcher::init(&url, FEEDUPDATE_SELECTOR)?;
        let store = PerItemDispatcher::new(redis_cache);
        let fu = feed::Update::init(oversion, 5, &loader, &store, verifier);
        if !fu.feed_is_outdated(current_feed).await.unwrap() {
            return Ok(());
        }
        fu.perform_update().await?;
        tracing::debug!("finished nasl feed update");
        Ok(())
    }
}

#[async_trait]
impl<T> ScanIDClientMapper for Storage<T>
where
    T: super::Storage + std::marker::Sync,
{
    async fn add_scan_client_id(
        &self,
        scan_id: String,
        client_id: ClientHash,
    ) -> Result<(), Error> {
        self.underlying.add_scan_client_id(scan_id, client_id).await
    }
    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        self.underlying.remove_scan_id(scan_id).await
    }

    async fn get_scans_of_client_id(&self, client_id: &ClientHash) -> Result<Vec<String>, Error> {
        self.underlying.get_scans_of_client_id(client_id).await
    }
}

#[async_trait]
impl<T> ProgressGetter for Storage<T>
where
    T: super::Storage + std::marker::Sync,
{
    async fn get_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        self.underlying.get_scan(id).await
    }

    async fn get_decrypted_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        self.underlying.get_decrypted_scan(id).await
    }

    async fn get_scan_ids(&self) -> Result<Vec<String>, Error> {
        self.underlying.get_scan_ids().await
    }

    async fn get_status(&self, id: &str) -> Result<Status, Error> {
        self.underlying.get_status(id).await
    }

    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        self.underlying.get_results(id, from, to).await
    }
}

impl From<redis::DbError> for super::Error {
    fn from(value: redis::DbError) -> Self {
        super::Error::Storage(Box::new(value))
    }
}

impl From<StorageError> for super::Error {
    fn from(value: StorageError) -> Self {
        super::Error::Storage(Box::new(value))
    }
}

#[async_trait]
impl<T> NVTStorer for Storage<T>
where
    T: super::Storage + std::marker::Sync + 'static,
{
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        tracing::debug!("starting feed update");

        let mut updates = JoinSet::new();
        {
            let mut h = self.hash.write().await;
            for ha in h.iter_mut() {
                if let Some(nh) = hash.iter().find(|x| x.typus == ha.typus) {
                    ha.hash.clone_from(&nh.hash)
                }
            }
        }

        for h in &hash {
            match h.typus {
                FeedType::NASL => {
                    let current_feed = self.current_feed_version().await?;
                    _ = updates.spawn(Self::update_nasl(
                        self.url.clone(),
                        h.path.clone(),
                        current_feed,
                    ))
                }
                FeedType::Advisories => {
                    _ = updates.spawn(Self::update_advisories(self.url.clone(), h.path.clone()))
                }
                FeedType::Products => {}
            };
        }
        while let Some(f) = updates.join_next().await {
            f.unwrap()?
        }

        tracing::debug!("finished feed update.");

        Ok(())
    }

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error> {
        let url = self.url.to_string();
        let aoid = oid.to_owned();
        let nr = tokio::task::spawn_blocking(move || {
            let mut notus_redis = RedisCtx::open(&url, NOTUSUPDATE_SELECTOR)?;
            notus_redis.redis_get_advisory(&aoid)
        })
        .await
        .unwrap()?;
        if nr.is_some() {
            return Ok(nr);
        }

        let aoid = oid.to_owned();
        let url = self.url.to_string();
        let nr = tokio::task::spawn_blocking(move || {
            let mut nvt_redis = RedisCtx::open(&url, FEEDUPDATE_SELECTOR)?;
            nvt_redis.redis_get_vt(&aoid)
        })
        .await
        .unwrap()?;
        Ok(nr)
    }
    async fn vts<'a>(
        &self,
    ) -> Result<Box<dyn Iterator<Item = scannerlib::storage::item::Nvt> + Send + 'a>, Error> {
        let url = self.url.to_string();
        let noids = tokio::task::spawn_blocking(move || {
            let mut notus_redis = RedisCtx::open(&url, NOTUSUPDATE_SELECTOR)?;
            let noids = notus_redis
                .keys("internal*")?
                .into_iter()
                .filter_map(|x| x.split('/').last().map(|x| x.to_string()))
                .filter_map(move |oid| notus_redis.redis_get_advisory(&oid).ok())
                .flatten();
            Ok::<_, Error>(noids)
        });

        let url = self.url.to_string();
        let foids = tokio::task::spawn_blocking(move || {
            let mut nvt_redis = RedisCtx::open(&url, FEEDUPDATE_SELECTOR)?;
            let foids = nvt_redis
                .keys("nvt:*")?
                .into_iter()
                .filter_map(|x| x.split('/').last().map(|x| x.to_string()))
                .filter_map(move |oid| nvt_redis.redis_get_vt(&oid[4..]).ok())
                .flatten();
            Ok::<_, Error>(foids)
        });

        let noids = noids.await.unwrap()?;
        let foids = foids.await.unwrap()?;
        let results = noids.chain(foids);
        Ok(Box::new(results))
    }

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        let url = Arc::new(self.url.to_string());
        let noids = tokio::task::spawn_blocking(move || {
            let mut notus_redis = RedisCtx::open(&url, NOTUSUPDATE_SELECTOR)?;
            let noids = notus_redis
                .keys("internal*")?
                .into_iter()
                .filter_map(|x| x.split('/').last().map(|x| x.to_string()));
            Ok::<_, Error>(noids)
        });

        let url = Arc::new(self.url.to_string());
        let foids = tokio::task::spawn_blocking(move || {
            let mut nvt_redis = RedisCtx::open(&url, FEEDUPDATE_SELECTOR)?;
            let foids = nvt_redis
                .keys("nvt:*")?
                .into_iter()
                .filter_map(|x| x.split('/').last().map(|x| x.to_string()));
            Ok::<_, Error>(foids)
        });

        let noids = noids.await.unwrap()?;
        let foids = foids.await.unwrap()?;
        let results = noids.chain(foids);
        Ok(Box::new(results))
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.hash.read().await.to_vec()
    }

    async fn current_feed_version(&self) -> Result<String, Error> {
        let url = self.url.to_string();
        let cache_version = tokio::task::spawn_blocking(move || {
            let mut cache = RedisCtx::open(&url, FEEDUPDATE_SELECTOR)?;
            let version = cache.lindex("nvticache", 0)?;
            if version.clone().is_empty() {
                let _ = cache.delete_namespace();
            }
            Ok::<_, Error>(version)
        })
        .await
        .unwrap()?;
        Ok(cache_version)
    }
}

#[async_trait]
impl<T> ScanStorer for Storage<T>
where
    T: super::Storage + std::marker::Sync,
{
    async fn insert_scan(&self, t: Scan) -> Result<(), Error> {
        self.underlying.insert_scan(t).await
    }
    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        self.underlying.remove_scan(id).await
    }
    async fn update_status(&self, id: &str, status: Status) -> Result<(), Error> {
        self.underlying.update_status(id, status).await
    }
}

#[async_trait]
impl<T> AppendFetchResult for Storage<T>
where
    T: super::Storage + std::marker::Sync,
{
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error> {
        self.underlying.append_fetched_result(results).await
    }
}

impl<T> FromConfigAndFeeds for Storage<T>
where
    T: FromConfigAndFeeds + std::marker::Sync + 'static,
{
    fn from_config_and_feeds(
        config: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self::new(
            T::from_config_and_feeds(config, feeds.clone())?,
            config.storage.redis.url.clone(),
            feeds,
        ))
    }
}

impl<S> super::ResultHandler for Storage<S>
where
    S: super::ResultHandler,
{
    fn underlying_storage(&self) -> &Arc<DefaultDispatcher> {
        self.underlying.underlying_storage()
    }

    fn handle_result<E>(&self, key: &ContextKey, result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>,
    {
        self.underlying.handle_result(key, result)
    }

    fn remove_result<E>(
        &self,
        key: &ContextKey,
        idx: Option<usize>,
    ) -> Result<Vec<models::Result>, E>
    where
        E: From<StorageError>,
    {
        self.underlying.remove_result(key, idx)
    }
}
