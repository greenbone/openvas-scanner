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
        match nvtcache.cache.max_db_index() {
            Ok(n) => println!("MAX: {}", n),
            Err(e) => println!("Error:{}", e),
        }

        if nvtcache.is_init() {
            println!("Is initialized");
        }

        match nvtcache.cache.set_namespace(1) {
            Ok(ok) => println!("Select 1 {}", ok),
            Err(e) => println!("Error:{}", e),
        }
        match nvtcache.cache.get_namespace() {
            Ok(ok) => println!("The namespace: {}", ok),
            Err(e) => println!("Error:{}", e),
        }

        let key = "key";
        let val = 42;
        match nvtcache.cache.redis_set_key_int(key, 42) {
            Ok(_) => println!("Key {} set with {}", key, val),
            Err(e) => println!("Error:{}", e),
        }
        println!("{}", nvtcache.cache.redis_get_int(key))
    }
}
