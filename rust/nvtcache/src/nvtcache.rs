use sink::Scope;
use sink::Sink;
use sink::SinkError;

use crate::dberror::DbError;
use crate::dberror::RedisResult;
use crate::nvt::*;
use crate::redisconnector::*;
use std::sync::Arc;
use std::sync::Mutex;

pub struct RedisNvtCache {
    pub cache: Arc<Mutex<RedisCtx>>,
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

    pub fn get_nvt_field(&self, oid: String, field: KbNvtPos) -> RedisResult<String> {
        let mut key: String = "nvt:".to_owned();
        key.push_str(oid.as_str());
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let value = cache.redis_get_item(key, field)?;
        Ok(value)
    }

    pub fn get_nvt_filename(&self, oid: &str) -> RedisResult<String> {
        let mut key: String = "nvt:".to_owned();
        key.push_str(oid);
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let filename = cache.redis_get_item(key, KbNvtPos::NvtFilenamePos)?;
        Ok(filename)
    }

    pub fn store_nvt(&self) -> RedisResult<()> {
            let nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
        let oid = nvtc.get_oid();
        let filename = nvtc.filename();
        let cached_nvt: String = self.get_nvt_filename(oid)?;

        // First check if there is a duplicate OID
        // If it is in the cache, and are not the same filename
        // we check if it is still in the filesystem.
        if !cached_nvt.is_empty() && cached_nvt != filename {
            // TODO
            //let mut src_path: String = self.plugin_path.to_owned();
            //src_path.push_str(&cached_nvt);

            // If still exists, the oid is duplicated
            // if Path::new(&src_path).exists() {
            //     println!(
            //         "NVT {src_path} with duplicate OID {oid} \
            //          will be replaced with {filename}"
            //     );
            // }
        }

        if !cached_nvt.is_empty() {
            let mut key: String = "nvt:".to_owned();
            key.push_str(oid.as_ref());
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
            let _ = cache.redis_del_key(key)?;
        }

        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.redis_add_nvt(nvtc.clone())?;
        
        Ok(())
    }
}

impl From<DbError> for SinkError {
    fn from(_: DbError) -> Self {
        Self {  }
    }
}

impl Sink for RedisNvtCache {
    fn store(&self, _key: &str, scope: sink::Scope) -> Result<(), sink::SinkError> {
        match scope {
            Scope::NVT(field) => {
                let mut nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
                match field {
                    sink::NVTKey::Oid(oid) => nvtc.set_oid(oid),
                    sink::NVTKey::FileName(name) => nvtc.set_filename(name),
                    sink::NVTKey::Name(name) => nvtc.set_name(name),
                    sink::NVTKey::Tag(key, value) => nvtc.add_tag(key.as_str().to_owned(), value),
                    sink::NVTKey::Dependencies(dependencies) => nvtc.set_dependencies(dependencies),
                    sink::NVTKey::RequiredKeys(rk) => nvtc.set_required_keys(rk),
                    sink::NVTKey::MandatoryKeys(mk) => nvtc.set_mandatory_keys(mk),
                    sink::NVTKey::ExcludedKeys(ek) => nvtc.set_excluded_keys(ek),
                    sink::NVTKey::RequiredPorts(rp) => nvtc.set_required_ports(rp),
                    sink::NVTKey::RequiredUdpPorts(rup) => nvtc.set_required_udp_ports(rup),
                    sink::NVTKey::Preference(pref) => nvtc.add_pref(pref),
                    sink::NVTKey::Category(cat) => nvtc.set_category(cat),
                    sink::NVTKey::Family(family) => nvtc.set_family(family),
                    sink::NVTKey::Reference(x) => nvtc.add_ref(x),
                    sink::NVTKey::NoOp => {
                        // script_version
                        // script_copyright
                        // are getting ignored. Although they're still being in NASL they have no functionality
                    },
                }
                Ok(())
            }
        }
    }

    fn get(&self, _key: &str) -> Result<Vec<sink::Scope>, sink::SinkError> {
        todo!()
    }

    fn on_exit(&self) -> Result<(), sink::SinkError> {
        self.store_nvt()?;
        Ok(())
    }
}
