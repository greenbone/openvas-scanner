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
    }
}
