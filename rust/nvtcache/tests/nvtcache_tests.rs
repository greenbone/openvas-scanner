use ::nvtcache::dberror::RedisResult;
use ::nvtcache::nvt::Nvt;
use ::nvtcache::redisconnector::KbNvtPos;
use nvtcache::nvtcache;

//test
#[cfg(test)]
mod test {
    use std::env;


    use super::*;

    #[test]
    // This is an integration test and requires a running redis instance.
    // Use cargo test --features=redis_test.
    // Also, set the environment variables REDIS_SOCKET and PLUGIN_PATH with valid paths
    #[cfg(feature = "redis_test")]
    fn integration_test_nvtcache() -> RedisResult<()> {
        let mut nvtcache: nvtcache::RedisNvtCache;

        let redis_default_socket = |_| "unix:///run/redis/redis-server.sock".to_string();
        let redis_socket = env::var("REDIS_SOCKET").unwrap_or_else(redis_default_socket);
        let default_plugin_path = |_| "/var/lib/openvas/plugins/".to_string();
        let plugin_path = env::var("PLUGIN_PATH").unwrap_or_else(default_plugin_path);
        nvtcache = nvtcache::RedisNvtCache::init(&redis_socket, &plugin_path)?;
        assert_eq!(nvtcache.is_init(), true);

        // Test get_namespace()
        assert!(nvtcache.cache.get_namespace()? > 0);

        let mut key = "key int value";
        let val: u64 = 42;

        // Test redis_set_key() generic with an uint value
        assert_eq!(nvtcache.cache.redis_set_key(key, val)?, ());

        // Test redis_get_key() with the recently stored key
        assert_eq!(nvtcache.cache.redis_get_key(key)?, val.to_string());

        // Test redis_set_key() generic with an string value
        key = "key string value";
        let val = "Some string";
        assert_eq!(nvtcache.cache.redis_set_key(key, val)?, ());

        assert_eq!(nvtcache.cache.redis_get_key(key)?, val);

        let _ = nvtcache.set_version("202212101125")?;
        assert_eq!(nvtcache.check_feed("202212101125")?, true);

        let mut fake_nvt: Nvt;
        fake_nvt = Nvt::new()?;

        let oid = "1234".to_owned();
        fake_nvt.set_oid(oid);
        fake_nvt.set_name("Custom Script for the vulnerability 1".to_owned());

        let pref = NvtPref::new(
            0,
            "entry".to_string(),
            "Timeout".to_string(),
            "320".to_string(),
        )?;
        fake_nvt.add_pref(pref);

        //Add first tag
        fake_nvt.add_tag("Tag Name".to_string(), "Tag Value".to_string());
        let tag = fake_nvt.get_tag();
        let expected = vec![("Tag Name".to_string(), "Tag Value".to_string())];
        assert_eq!(tag, &expected);

        //Add second tag cvss_base, which is ignored
        fake_nvt.add_tag("cvss_base".to_string(), "Tag Value1".to_string());
        let tag = fake_nvt.get_tag();
        let expected = vec![("Tag Name".to_string(), "Tag Value".to_string())];
        assert_eq!(tag, &expected);

        let filename = "custom.nasl".to_owned();
        assert_eq!(nvtcache.add_nvt(fake_nvt, filename)?, ());

        let mut item = nvtcache.get_nvt_field("1234".to_owned(), KbNvtPos::NvtFilenamePos)?;
        assert_eq!(item, "custom.nasl");

        item = nvtcache.get_nvt_field("1234".to_owned(), KbNvtPos::NvtNamePos)?;
        assert_eq!(item, "Custom Script for the vulnerability 1");

        item = nvtcache.get_nvt_field("1234".to_owned(), KbNvtPos::NvtTagsPos)?;
        assert_eq!(item, "Tag Name=Tag Value");

        let _ = nvtcache.reset();

        Ok(())
    }
}
