const NVTCACHE: &str = "nvticache";

pub mod nvtcache {

    use super::*;
    use crate::dberror::dberror::Result;
    use crate::redisconnector::redisconnector::*;

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
        pub fn set_nvtcache_version(&mut self, feed_version: &str) -> Result<()> {
            let _ = self.cache.redis_set_key("nvticache", feed_version)?;
            Ok(())
        }

        /// Get the key nvtcache, which has the feed version
        pub fn get_nvtcache_version(&mut self) -> Result<String> {
            let version = self.cache.redis_get_key("nvticache")?;
            Ok(version)
        }
    }
}
