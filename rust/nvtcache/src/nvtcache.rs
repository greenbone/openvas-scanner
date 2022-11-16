use crate::dberror::Result;
use crate::nvt::*;
use crate::redisconnector::*;
use std::path::Path;

pub struct NvtCache<'a> {
    pub cache: RedisCtx,
    pub init: bool,
    cache_key: &'a str,
    plugin_path: &'a str,
}

/// NvtCache implementation.
impl<'a> NvtCache<'a> {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    /// While the plugin_path is given without the protocol infix.
    /// The reason is that while redis can be configured to use tcp the plugins must be available within the filesystem.
    pub fn init(redis_url: &'a str, plugin_path: &'a str) -> Result<NvtCache<'a>> {
        let rctx = RedisCtx::new(redis_url)?;

        let cache_key = "nvticache";

        Ok(NvtCache {
            cache: rctx,
            init: true,
            cache_key,
            plugin_path,
        })
    }

    /// Return a bool telling if the NVT Cache is initialized
    pub fn is_init(&mut self) -> bool {
        self.init
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&mut self) -> Result<()> {
        self.cache.delete_namespace()
    }

    /// Set the key nvtcache
    pub fn set_version(&mut self, feed_version: &str) -> Result<()> {
        self.cache.redis_set_key(self.cache_key, feed_version)
    }

    /// Get the key nvtcache, which has the feed version
    pub fn get_version(&mut self) -> Result<String> {
        self.cache.redis_get_key(self.cache_key)
    }

    /// Check if the nvtcache is uptodate, comparing the feed version
    /// in the filesystem (in plugin_feed_info.inc) and compare it
    /// with the version in the cache
    /// Return True if it is updated, False if outdated, Error otherwise.
    pub fn check_feed(&mut self, current: &str) -> Result<bool> {
        let cached = self.cache.redis_get_key(self.cache_key)?;
        if cached == current {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn get_nvt_field(&mut self, oid: String, field: KbNvtPos) -> Result<String> {
        let mut key: String = "nvt:".to_owned();
        key.push_str(oid.as_str());
        let value = self.cache.redis_get_item(key, field)?;
        Ok(value)
    }

    pub fn get_nvt_filename(&mut self, oid: &str) -> Result<String> {
        let mut key: String = "nvt:".to_owned();
        key.push_str(oid);
        let filename = self.cache.redis_get_item(key, KbNvtPos::NvtFilenamePos)?;
        Ok(filename)
    }

    pub fn add_nvt(&mut self, nvt: Nvt, filename: String) -> Result<()> {
        let oid = nvt.get_oid();
        let cached_nvt: String = self.get_nvt_filename(&oid)?;

        // First check if there is a duplicate OID
        // If it is in the cache, and are not the same filename
        // we check if it is still in the filesystem.
        if !cached_nvt.is_empty() && cached_nvt != filename {
            let mut src_path: String = self.plugin_path.to_owned();
            src_path.push_str(&cached_nvt);

            // If still exists, the oid is duplicated
            if Path::new(&src_path).exists() {
                println!(
                    "NVT {src_path} with duplicate OID {oid} \
                     will be replaced with {filename}"
                );
            }
        }

        if !cached_nvt.is_empty() {
            let mut key: String = "nvt:".to_owned();
            key.push_str(oid.as_ref());
            let _ = self.cache.redis_del_key(key)?;
        }

        self.cache.redis_add_nvt(nvt, filename)?;
        Ok(())
    }
}
