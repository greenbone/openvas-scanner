const NVTCACHE: &str = "nvticache";
const PLUGIN_PATH: &str = "/home/jnicola/install/var/lib/openvas/plugins/";

use crate::dberror::Result;
use crate::nvt::*;
use crate::redisconnector::*;
use std::path::Path;

pub struct NvtCache {
    pub cache: RedisCtx,
    pub init: bool,
}

/// NvtCache implementation.
impl NvtCache {
    /// Initialize and return an NVT Cache Object
    pub fn init() -> Result<NvtCache> {
        let rctx = RedisCtx::new()?;
        Ok(NvtCache {
            cache: rctx,
            init: true,
        })
    }

    /// Return a bool telling if the NVT Cache is initialized
    pub fn is_init(&mut self) -> bool {
        self.init == true
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&mut self) -> Result<()> {
        let _ = self.cache.delete_namespace()?;
        Ok(())
    }

    /// Set the key nvtcache
    pub fn set_version(&mut self, feed_version: &str) -> Result<()> {
        let _ = self.cache.redis_set_key("nvticache", feed_version)?;
        Ok(())
    }

    /// Get the key nvtcache, which has the feed version
    pub fn get_version(&mut self) -> Result<String> {
        let version = self.cache.redis_get_key("nvticache")?;
        Ok(version)
    }

    /// Check if the nvtcache is uptodate, comparing the feed version
    /// in the filesystem (in plugin_feed_info.inc) and compare it
    /// with the version in the cache
    /// Return True if it is updated, False if outdated, Error otherwise.
    pub fn check_feed(&mut self, current: &str) -> Result<bool> {
        let cached = self.cache.redis_get_key("nvticache")?;
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

    pub fn get_nvt_filename(&mut self, oid: &String) -> Result<String> {
        let mut key: String = "nvt:".to_owned();
        key.push_str(oid);
        let filename = self.cache.redis_get_item(key, KbNvtPos::NvtFilenamePos)?;
        Ok(filename)
    }

    pub fn add_nvt(&mut self, mut nvt: Nvt, filename: String) -> Result<()> {
        let oid = nvt.get_oid()?;
        let cached_nvt: String = self.get_nvt_filename(&oid)?;

        // First check if there is a duplicate OID
        // If it is in the cache, and are not the same filename
        // we check if it is still in the filesystem.
        if !cached_nvt.is_empty() && cached_nvt != filename {
            let mut src_path: String = PLUGIN_PATH.to_owned();
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
