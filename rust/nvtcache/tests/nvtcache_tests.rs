use nvtcache::nvtcache;
use std::error::Error;

//test
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nvtcache() {
        let mut nvtcache: nvtcache::nvtcache::NvtCache;
        let n = nvtcache::nvtcache::NvtCache::init();
        match n {
            Ok(nc) => nvtcache = nc,
            Err(e) => {
                println!("{}", e);
                if let Some(source) = e.source() {
                    println!("{}", source);
                }

                panic!("Error")
            }
        }

        if nvtcache.is_init() {
            println!("Is initialized");
        }

        match nvtcache.cache.get_namespace() {
            Ok(ok) => println!("The namespace: {}", ok),
            Err(e) => println!("Error:{}", e),
        }

        let mut key = "key int value";
        let val: u64 = 42;
        match nvtcache.cache.redis_set_key(key, val) {
            Ok(_) => println!("Key {} set with {}", key, val),
            Err(e) => println!("Error:{}", e),
        }
        let res = nvtcache.cache.redis_get_key(key);
        match res {
            Ok(k) => println!("{}", k),
            Err(_) => println!("Error"),
        }

        key = "key string value";
        let val = "Some string";
        match nvtcache.cache.redis_set_key(key, val) {
            Ok(_) => println!("Key {} set with {}", key, val),
            Err(e) => println!("Error:{}", e),
        }

        let res = nvtcache.cache.redis_get_key(key);
        match res {
            Ok(k) => println!("{}", k),
            Err(_) => println!("Error"),
        }

        let _ = nvtcache.set_nvtcache_version("202212101125");
        let version = nvtcache.get_nvtcache_version();
        match version {
            Ok(v) => assert_eq!(v, "202212101125"),
            Err(_) => println!("Error"),
        }

        let _ = nvtcache.reset();
    }
}
