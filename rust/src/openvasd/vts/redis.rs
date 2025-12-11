use std::{path::PathBuf, task::Poll};

use futures::Stream;
use greenbone_scanner_framework::GetVTsError;
use scannerlib::{
    models::{FeedType, VTData},
    openvas::cmd,
    storage::redis::{
        CACHE_KEY, DbError, NOTUS_KEY, RedisAddAdvisory, RedisAddNvt, RedisCtx, RedisGetNvt,
        RedisWrapper,
    },
};

use crate::{
    config::Config,
    vts::{
        FeedHash, PluginFetcher, PluginStorer, error_vts_error,
        orchestrator::{self, WorkerError},
    },
};

pub struct FeedSynchronizer {
    plugin_feed: PathBuf,
    advisory_feed: PathBuf,
    signature_check: bool,
    address: String,
    plugin_storer: RedisPluginHandler,
}

impl FeedSynchronizer {
    pub fn new(config: &Config) -> Self {
        let address = cmd::get_redis_socket();
        let plugin_feed = config.feed.path.clone();
        let advisory_feed = config.notus.advisories_path.clone();
        let signature_check = config.feed.signature_check;
        let plugin_storer = RedisPluginHandler {
            address: address.clone(),
        };
        Self {
            plugin_feed,
            advisory_feed,
            signature_check,
            address,
            plugin_storer,
        }
    }
}

impl From<&Config> for FeedSynchronizer {
    fn from(value: &Config) -> Self {
        Self::new(value)
    }
}

type R<T> = Result<T, GetVTsError>;

fn init_redis_storage(redis_url: &str, ft: FeedType) -> R<RedisCtx> {
    use scannerlib::storage::redis::*;
    let selector = match ft {
        FeedType::Products | FeedType::Advisories => NOTUSUPDATE_SELECTOR,
        FeedType::NASL => FEEDUPDATE_SELECTOR,
    };
    RedisCtx::open(redis_url, selector).map_err(error_vts_error)
}

#[derive(Debug, Clone)]
pub struct RedisPluginHandler {
    address: String,
}

impl From<&Config> for RedisPluginHandler {
    fn from(_: &Config) -> Self {
        Self {
            address: cmd::get_redis_socket(),
        }
    }
}

fn redis_error_to_worker_error(error: DbError) -> WorkerError {
    WorkerError::Sync(GetVTsError::External(Box::new(error)))
}

fn redis_with_hash<T, F>(
    address: String,
    hash: &super::FeedHash,
    f: F,
) -> scannerlib::PinBoxFut<Result<T, WorkerError>>
where
    F: Fn(RedisCtx, FeedType, String) -> Result<T, WorkerError> + Send + 'static,
    T: Send + 'static,
{
    let kind = hash.typus;
    let hash = hash.hash.clone();
    redis_with_feed_type(address, kind, move |r, k| f(r, k, hash.clone()))
}

fn redis_with_feed_type<T, F>(
    address: String,
    kind: FeedType,
    f: F,
) -> scannerlib::PinBoxFut<Result<T, WorkerError>>
where
    F: Fn(RedisCtx, FeedType) -> Result<T, WorkerError> + Send + 'static,
    T: Send + 'static,
{
    Box::pin(async move {
        tokio::task::spawn_blocking(move || {
            let rctx = init_redis_storage(&address, kind)?;
            f(rctx, kind)
        })
        .await
        .unwrap()
    })
}

struct RedisOidStream {
    address: String,
    nasl_oid_cache: Option<Vec<String>>,
    advi_oid_cache: Option<Vec<String>>,
}

impl RedisOidStream {
    fn may_init_oids_nasl(&mut self) -> Result<Vec<String>, WorkerError> {
        let mut rctx = init_redis_storage(&self.address, FeedType::NASL)?;
        let keys = rctx.keys("nvt:*").map_err(redis_error_to_worker_error)?;
        Ok(keys
            .iter()
            .map(|x| x.strip_prefix("nvt:").unwrap_or("invalid").to_string())
            .collect())
    }

    fn get_next_nasl(&mut self) -> Option<Result<String, WorkerError>> {
        if self.nasl_oid_cache.is_none() {
            match self.may_init_oids_nasl() {
                Ok(oids) => self.nasl_oid_cache = Some(oids),
                Err(error) => return Some(Err(error)),
            }
        }
        if let Some(narf) = self.nasl_oid_cache.as_mut() {
            narf.pop().map(Ok)
        } else {
            None
        }
    }

    fn may_init_oids_advisories(&mut self) -> Result<Vec<String>, WorkerError> {
        let mut rctx = init_redis_storage(&self.address, FeedType::Advisories)?;
        let keys = rctx
            .keys("internal/notus/advisories/*")
            .map_err(redis_error_to_worker_error)?;
        Ok(keys
            .iter()
            .map(|x| {
                x.strip_prefix("internal/notus/advisories/")
                    .unwrap_or("invalid_advi")
                    .to_string()
            })
            .collect())
    }

    fn get_next_advisory(&mut self) -> Option<Result<String, WorkerError>> {
        if self.advi_oid_cache.is_none() {
            match self.may_init_oids_advisories() {
                Ok(oids) => self.advi_oid_cache = Some(oids),
                Err(error) => return Some(Err(error)),
            }
        }
        if let Some(narf) = self.advi_oid_cache.as_mut() {
            narf.pop().map(Ok)
        } else {
            None
        }
    }
}

impl From<String> for RedisOidStream {
    fn from(value: String) -> Self {
        Self {
            address: value,
            nasl_oid_cache: None,
            advi_oid_cache: None,
        }
    }
}

impl Stream for RedisOidStream {
    type Item = Result<String, WorkerError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let that = self.get_mut();
        match that.get_next_nasl() {
            Some(x) => Poll::Ready(Some(x)),
            None => Poll::Ready(that.get_next_advisory()),
        }
    }
}

struct RedisVTDataStream {
    ros: RedisOidStream,
}

impl From<String> for RedisVTDataStream {
    fn from(value: String) -> Self {
        Self {
            ros: RedisOidStream::from(value),
        }
    }
}

impl RedisVTDataStream {
    fn get_vtdata_nasl(&mut self) -> Option<Result<VTData, WorkerError>> {
        let oid = match self.ros.get_next_nasl()? {
            Ok(oid) => oid,
            Err(error) => return Some(Err(error)),
        };
        match init_redis_storage(&self.ros.address, FeedType::NASL) {
            Ok(mut rctx) => match rctx.redis_get_vt(&oid) {
                Ok(x) => x.map(Ok),
                Err(error) => Some(Err(redis_error_to_worker_error(error))),
            },
            Err(error) => Some(Err(error.into())),
        }
    }

    fn get_vtdata_advi(&mut self) -> Option<Result<VTData, WorkerError>> {
        let oid = match self.ros.get_next_advisory()? {
            Ok(oid) => oid,
            Err(error) => return Some(Err(error)),
        };
        match init_redis_storage(&self.ros.address, FeedType::Advisories) {
            Ok(mut rctx) => match rctx.redis_get_advisory(&oid) {
                Ok(x) => x.map(Ok),
                Err(error) => Some(Err(redis_error_to_worker_error(error))),
            },
            Err(error) => Some(Err(error.into())),
        }
    }
}

impl Stream for RedisVTDataStream {
    type Item = Result<VTData, WorkerError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let that = self.get_mut();
        match that.get_vtdata_nasl() {
            Some(x) => Poll::Ready(Some(x)),
            None => Poll::Ready(that.get_vtdata_advi()),
        }
    }
}

impl PluginFetcher for RedisPluginHandler {
    fn get_oids(&self) -> greenbone_scanner_framework::StreamResult<'static, String, WorkerError> {
        Box::new(RedisOidStream::from(self.address.clone()))
    }

    fn get_vts(
        &self,
    ) -> greenbone_scanner_framework::StreamResult<'static, scannerlib::models::VTData, WorkerError>
    {
        Box::new(RedisVTDataStream::from(self.address.clone()))
    }
}

impl PluginStorer for RedisPluginHandler {
    fn store_hash(&self, hash: &super::FeedHash) -> scannerlib::PinBoxFut<Result<(), WorkerError>> {
        redis_with_hash(self.address.clone(), hash, |mut rctx, kind, hash| {
            tracing::debug!(?kind, ?hash, "Changing hash");
            if kind == FeedType::NASL {
                rctx.del(CACHE_KEY)
                    .and_then(move |_| rctx.rpush(CACHE_KEY, &[&hash]))
            } else {
                rctx.del(NOTUS_KEY)
                    .and_then(move |_| rctx.rpush(NOTUS_KEY, &[&hash]))
            }
            .map_err(redis_error_to_worker_error)
        })
    }

    fn store_plugin<T>(
        &self,
        hash: &super::FeedHash,
        plugin: T,
    ) -> scannerlib::PinBoxFut<Result<(), WorkerError>>
    where
        T: super::Plugin + Send + Sync + 'static,
    {
        redis_with_feed_type(self.address.clone(), hash.typus, move |mut rctx, kind| {
            match kind {
                scannerlib::models::FeedType::Products
                | scannerlib::models::FeedType::Advisories => {
                    rctx.redis_add_advisory(plugin.advisory().cloned())
                }
                scannerlib::models::FeedType::NASL => match plugin.vulnerability_test().cloned() {
                    None => {
                        unreachable!("FeedType::NASL must have vulnerability test data.")
                    }
                    Some(vt) => rctx.redis_add_nvt(vt),
                },
            }
            .map_err(redis_error_to_worker_error)
        })
    }
}

impl orchestrator::Worker for FeedSynchronizer {
    fn cached_hashes(
        &self,
    ) -> scannerlib::PinBoxFut<Result<Option<super::FeedHashes>, orchestrator::WorkerError>> {
        let address = self.address.clone();
        let feed_version = |address: &str, ft: FeedType| -> Result<Option<String>, WorkerError> {
            let key = match &ft {
                FeedType::NASL => CACHE_KEY,
                _ => NOTUS_KEY,
            };
            let mut nasl_ctx = init_redis_storage(address, ft)?;
            let mut ck = nasl_ctx
                .lrange(key, 0, 0)
                .map_err(redis_error_to_worker_error)?;
            Ok(ck.pop())
        };
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let vtc = feed_version(&address, FeedType::NASL)?;
                let nc = feed_version(&address, FeedType::Advisories)?;

                Ok(match (vtc, nc) {
                    (None, None) => None,
                    (nasl, notus) => Some((nasl.unwrap_or_default(), notus.unwrap_or_default())),
                })
            })
            .await
            .unwrap()
        })
    }

    fn update_feed(
        &self,
        kind: FeedType,
        new_hash: String,
    ) -> scannerlib::PinBoxFut<Result<(), orchestrator::WorkerError>> {
        let ps = self.plugin_storer.clone();
        let path = match kind {
            FeedType::Products | FeedType::Advisories => self.advisory_feed(),
            FeedType::NASL => self.plugin_feed(),
        };
        let feed_hash = FeedHash {
            hash: new_hash,
            path,
            typus: kind,
        };
        let verify = self.signature_check;
        Box::pin(async move { super::synchronize_feed(&ps, feed_hash, verify).await })
    }

    fn signature_check(&self) -> bool {
        self.signature_check
    }

    fn plugin_feed(&self) -> PathBuf {
        self.plugin_feed.clone()
    }

    fn advisory_feed(&self) -> PathBuf {
        self.advisory_feed.clone()
    }
}
