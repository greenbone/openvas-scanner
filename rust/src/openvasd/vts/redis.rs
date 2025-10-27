use std::path::PathBuf;

use greenbone_scanner_framework::GetVTsError;
use scannerlib::{
    models::FeedType,
    storage::redis::{
        CACHE_KEY, DbError, NOTUS_KEY, RedisAddAdvisory, RedisAddNvt, RedisCtx, RedisWrapper,
    },
};

use crate::vts::{
    FeedHash, PluginStorer, error_vts_error,
    orchestrator::{self, WorkerError},
};

pub struct FeedSynchronizer {
    plugin_feed: PathBuf,
    advisory_feed: PathBuf,
    signature_check: bool,
    address: String,
    plugin_storer: RedisPluginHandler,
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
struct RedisPluginHandler {
    address: String,
}

fn redis_error_to_worker_error(error: DbError) -> WorkerError {
    WorkerError::Sync(GetVTsError::External(Box::new(error)))
}

fn bpttsrkh<T, F>(
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
    Box::pin(async move {
        tokio::task::spawn_blocking(move || {
            let rctx = init_redis_storage(&address, kind)?;
            f(rctx, kind, hash)
        })
        .await
        .unwrap()
    })
}

impl PluginStorer for RedisPluginHandler {
    fn store_hash(&self, hash: &super::FeedHash) -> scannerlib::PinBoxFut<Result<(), WorkerError>> {
        bpttsrkh(self.address.clone(), hash, |mut rctx, kind, hash| {
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
        bpttsrkh(self.address.clone(), hash, move |mut rctx, kind, _| {
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
        Box::pin(async move { super::synchronize_feed(&ps, feed_hash).await })
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
