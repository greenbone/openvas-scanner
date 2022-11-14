use ::nvtcache::dberror::Result;
use ::nvtcache::nvt::Nvt;
use ::nvtcache::redisconnector::KbNvtPos;
use nvtcache::nvtcache;
use std::error::Error;

//test
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nvtcache() -> Result<()> {
        let mut nvtcache: nvtcache::NvtCache;
        let n = nvtcache::NvtCache::init();
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

        let _ = nvtcache.set_version("202212101125");
        let updated = nvtcache.check_feed("202212101125");
        match updated {
            Ok(ret) => {
                assert_eq!(ret, true);
                println!("Feed up-to-date");
            }
            Err(_) => println!("Error"),
        }

        let mut fake_nvt: Nvt;
        let res = Nvt::new();
        match res {
            Ok(ok) => fake_nvt = ok,
            Err(_) => panic!("No Nvt"),
        }

        let oid = "1234".to_owned();
        match fake_nvt.set_oid(oid) {
            Ok(_) => (),
            Err(_) => println!("Error"),
        }
        match fake_nvt.set_name("Custom Script for the vulnerability 1".to_owned()) {
            Ok(_) => (),
            Err(_) => println!("Error"),
        }
        let filename = "custom.nasl".to_owned();
        match nvtcache.add_nvt(fake_nvt, filename) {
            Ok(_) => println!("Nvt successfully added"),
            Err(_) => println!("Error"),
        }

        let mut item = nvtcache.get_nvt_field("1234".to_owned(), KbNvtPos::NvtFilenamePos)?;
        assert_eq!(item, "custom.nasl");
        println!("The filename was fetch successfully: {}", item);

        item = nvtcache.get_nvt_field("1234".to_owned(), KbNvtPos::NvtNamePos)?;
        assert_eq!(item, "Custom Script for the vulnerability 1");

        let _ = nvtcache.reset();

        return Ok(());
    }
}
