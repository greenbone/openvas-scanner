use ::nvtcache::dberror::RedisResult;
use ::nvtcache::nvt::Nvt;
use ::nvtcache::redisconnector::KbNvtPos;
use nvtcache::nvtcache;

//test
#[cfg(test)]
#[cfg(feature = "redis_test")]
mod test {

    use sink::NVTField::*;
    use sink::NVTKey;
    use sink::NvtRef;
    use sink::Sink;
    use sink::StoreType::NVT;
    use sink::TagKey::*;
    use sink::ACT::*;

    use std::env;

    use ::nvtcache::redisconnector::RedisCtx;

    use super::*;

    #[test]
    fn redis_ctx() {
        let socket = {
            let redis_default_socket = |_| "unix:///run/redis/redis-server.sock".to_string();
            env::var("REDIS_SOCKET").unwrap_or_else(redis_default_socket)
        };
        let mut rctx = RedisCtx::new(&socket).unwrap();
        rctx.redis_set_key("int value", 42).unwrap();
        assert_eq!(rctx.redis_key("int value").unwrap(), "42".to_owned());

        rctx.redis_set_key("string value", "moep").unwrap();
        assert_eq!(
            rctx.redis_key("string value").unwrap(),
            "moep".to_owned()
        );
    }

    #[test]
    // This is an integration test and requires a running redis instance.
    // Use cargo test --features=redis_test.
    // Also, set the environment variables REDIS_SOCKET and PLUGIN_PATH with valid paths
    fn integration_test_nvtcache() -> RedisResult<()> {

        let socket = {
            let redis_default_socket = |_| "unix:///run/redis/redis-server.sock".to_string();
            env::var("REDIS_SOCKET").unwrap_or_else(redis_default_socket)
        };
        let nvtcache = nvtcache::RedisNvtCache::init(&socket)?;

        // Test get_namespace()
        //assert!(nvtcache.cache.get_namespace()? > 0);

        // TODO translate to scope commands
        let _ = nvtcache.set_version("202212101125")?;
        assert_eq!(nvtcache.check_feed("202212101125")?, true);

        let commands = [
            NVT(FileName("test.nasl".to_owned())),
            NVT(Oid("0.0.0.0.0.0.0.0.0.1".to_owned())),
            NVT(Tag(
                CreationDate,
                "2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)".to_owned(),
            )),
            NVT(Name("that is a very long and descriptive name".to_owned())),
            NVT(Category(Denial)),
            NVT(Family("Denial of Service".to_owned())),
            NVT(Dependencies(vec![
                "ssh_detect.nasl".to_owned(),
                "ssh2.nasl".to_owned(),
            ])),
            NVT(RequiredPorts(vec![
                "Services/ssh".to_owned(),
                "22".to_owned(),
            ])),
            NVT(MandatoryKeys(vec!["ssh/blubb/detected".to_owned()])),
            NVT(Reference(NvtRef {
                class: "http://freshmeat.sourceforge.net/projects/eventh/".to_owned(),
                id: "URL".to_owned(),
                text: None,
            })),
            NVT(ExcludedKeys(vec![
                "Settings/disable_cgi_scanning".to_owned(),
                "bla/bla".to_owned(),
            ])),
            NVT(RequiredUdpPorts(vec![
                "Services/udp/unknown".to_owned(),
                "17".to_owned(),
            ])),
            NVT(Reference(NvtRef {
                class: "cve".to_owned(),
                id: "CVE-1999-0524".to_owned(),
                text: None,
            })),
            NVT(RequiredKeys(vec!["WMI/Apache/RootPath".to_owned()])),
        ];
        for c in commands {
            nvtcache.store("test.nasl", c).unwrap();
        }
        nvtcache.on_exit().unwrap();
        let x = nvtcache
            .get(
                "0.0.0.0.0.0.0.0.0.1",
                sink::GetType::NVT(Some(NVTKey::FileName)),
            )
            .unwrap();
        assert_eq!(x, vec![]);

        Ok(())
    }
}
