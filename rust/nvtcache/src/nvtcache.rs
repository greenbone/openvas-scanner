pub mod nvtcache {

    //    use super::*;
    use crate::dberror::dberror::Result;
    use crate::redisconnector::redisconnector::*;

    pub struct NvtCache {
        pub cache: RedisCtx,
        pub init: bool,
    }

    /// NvtCache implementation.
    impl NvtCache {
        /// initialize the NVT Cache.
        pub fn init() -> Result<NvtCache> {
            let mut rctx = RedisCtx::new()?;
            let kbi = rctx.select_database()?;
            Ok(NvtCache {
                cache: rctx,
                init: true,
            })
        }

        pub fn is_init(&mut self) -> bool {
            self.init == true
        }
    }
}
