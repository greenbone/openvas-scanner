use sink::GetType;
use sink::NVTKey;
use sink::Sink;
use sink::SinkError;
use sink::StoreType;

use crate::dberror::DbError;
use crate::dberror::RedisResult;
use crate::nvt::*;
use crate::redisconnector::*;
use std::sync::Arc;
use std::sync::Mutex;

pub struct RedisNvtCache {
    cache: Arc<Mutex<RedisCtx>>,
    // The current redis implementation needs a complete NVT object to work with
    // due to the defined ordering.
    // Therefore it caches it until on exit is called.
    internal_cache: Arc<Mutex<Nvt>>,
}

const CACHE_KEY: &str = "nvticache";

/// NvtCache implementation.
impl RedisNvtCache {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    /// While the plugin_path is given without the protocol infix.
    /// The reason is that while redis can be configured to use tcp the plugins must be available within the filesystem.
    // TODO initialize redis ctx before
    pub fn init(redis_url: &str) -> RedisResult<RedisNvtCache> {
        let rctx = RedisCtx::new(redis_url)?;

        Ok(RedisNvtCache {
            cache: Arc::new(Mutex::new(rctx)),
            internal_cache: Arc::new(Mutex::new(Nvt::default())),
        })
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&self) -> RedisResult<()> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.delete_namespace()
    }

    // TODO move that out of here

    /// Set the key nvtcache
    pub fn set_version(&self, feed_version: &str) -> RedisResult<()> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.redis_set_key(CACHE_KEY, feed_version)
    }

    /// Get the key nvtcache, which has the feed version
    pub fn get_version(&self) -> RedisResult<String> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.redis_get_key(CACHE_KEY)
    }

    /// Check if the nvtcache is uptodate, comparing the feed version
    /// in the filesystem (in plugin_feed_info.inc) and compare it
    /// with the version in the cache
    /// Return True if it is updated, False if outdated, Error otherwise.
    pub fn check_feed(&self, current: &str) -> RedisResult<bool> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let cached = cache.redis_get_key(CACHE_KEY)?;
        if cached == current {
            return Ok(true);
        }
        Ok(false)
    }
    // END TODO

    pub fn get_nvt_field(&self, oid: String, field: KbNvtPos) -> RedisResult<String> {
        let mut key: String = "nvt:".to_owned();
        key.push_str(oid.as_str());
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let value = cache.lindex(key, field)?;
        Ok(value)
    }

    pub fn get_nvt_filename(&self, oid: &str) -> RedisResult<String> {
        let mut key: String = "nvt:".to_owned();
        key.push_str(oid);
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let filename = cache.lindex(key, KbNvtPos::Filename)?;
        Ok(filename)
    }




    pub fn store_nvt(&self) -> RedisResult<()> {
        let nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
        // TODO add oid duplicate check on interpreter

        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.redis_add_nvt(nvtc.clone()).unwrap();

        Ok(())
    }
}

impl From<DbError> for SinkError {
    fn from(_: DbError) -> Self {
        Self {}
    }
}

impl Sink for RedisNvtCache {
    fn store(&self, _key: &str, scope: sink::StoreType) -> Result<(), sink::SinkError> {
        match scope {
            StoreType::NVT(field) => {
                let mut nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
                match field {
                    sink::NVTField::Oid(oid) => nvtc.set_oid(oid),
                    sink::NVTField::FileName(name) => nvtc.set_filename(name),
                    sink::NVTField::Name(name) => nvtc.set_name(name),
                    sink::NVTField::Tag(key, value) => nvtc.add_tag(key.as_str().to_owned(), value),
                    sink::NVTField::Dependencies(dependencies) => {
                        nvtc.set_dependencies(dependencies)
                    }
                    sink::NVTField::RequiredKeys(rk) => nvtc.set_required_keys(rk),
                    sink::NVTField::MandatoryKeys(mk) => nvtc.set_mandatory_keys(mk),
                    sink::NVTField::ExcludedKeys(ek) => nvtc.set_excluded_keys(ek),
                    sink::NVTField::RequiredPorts(rp) => nvtc.set_required_ports(rp),
                    sink::NVTField::RequiredUdpPorts(rup) => nvtc.set_required_udp_ports(rup),
                    sink::NVTField::Preference(pref) => nvtc.add_pref(pref),
                    sink::NVTField::Category(cat) => nvtc.set_category(cat),
                    sink::NVTField::Family(family) => nvtc.set_family(family),
                    sink::NVTField::Reference(x) => nvtc.add_ref(x),
                    sink::NVTField::NoOp => {
                        // script_version
                        // script_copyright
                        // are getting ignored. Although they're still being in NASL they have no functionality
                    }
                }
                Ok(())
            }
        }
    }

    fn on_exit(&self) -> Result<(), sink::SinkError> {
        self.store_nvt()?;
        Ok(())
    }

    fn get(&self, key: &str, scope: sink::GetType) -> Result<Vec<StoreType>, SinkError> {
        let rkey = format!("nvt:{}", key);
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        match scope {
            GetType::NVT(nvt) => match nvt {
                Some(x) => match x {
                    NVTKey::Oid => Ok(vec![StoreType::NVT(sink::NVTField::Oid(key.to_owned()))]),
                    NVTKey::FileName => {
                        let pos = KbNvtPos::try_from(x)?;
                        let strresult = cache.lindex(rkey, pos)?;
                        Ok(vec![StoreType::NVT(sink::NVTField::FileName(strresult))])
                    }
                    NVTKey::Name => todo!(),
                    NVTKey::Tag => todo!(),
                    NVTKey::Dependencies => todo!(),
                    NVTKey::RequiredKeys => todo!(),
                    NVTKey::MandatoryKeys => todo!(),
                    NVTKey::ExcludedKeys => todo!(),
                    NVTKey::RequiredPorts => todo!(),
                    NVTKey::RequiredUdpPorts => todo!(),
                    NVTKey::Preference => todo!(),
                    NVTKey::Reference => todo!(),
                    NVTKey::Category => todo!(),
                    NVTKey::Family => todo!(),
                    NVTKey::NoOp => todo!(),
                },
                None => todo!(),
            },
        }
    }
}
