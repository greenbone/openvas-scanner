// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
#[cfg(feature = "redis_test")]
// This is an integration test and requires a running redis instance.
// Use cargo test --features=redis_test.
// Also, set the environment variables REDIS_SOCKET and PLUGIN_PATH with valid paths
mod test {

    use redis_sink::connector::NameSpaceSelector;
    use redis_sink::dberror::RedisSinkResult;
    use sink::nvt::NVTField::*;
    use sink::nvt::NVTKey;
    use sink::nvt::NvtPreference;
    use sink::nvt::NvtRef;
    use sink::nvt::PreferenceType;
    use sink::nvt::TagKey::*;
    use sink::nvt::ACT::*;
    use sink::Dispatch::NVT;
    use sink::Sink;

    use std::env;

    use redis_sink::connector::{RedisCache, RedisCtx};

    fn redis_url() -> &'static str {
        option_env!("REDIS_URL").unwrap_or("unix:///run/redis/redis.sock")
    }

    #[test]
    fn redis_ctx() {
        let mut rctx = RedisCtx::open(redis_url(), &[NameSpaceSelector::Free]).unwrap();
        rctx.set_value("int value", 42).unwrap();
        assert_eq!(rctx.value("int value").unwrap(), "42".to_owned());
        rctx.set_value("string value", "moep").unwrap();
        assert_eq!(rctx.value("string value").unwrap(), "moep".to_owned());
        let mut aha =
            RedisCtx::open(redis_url(), &[NameSpaceSelector::Key("string value")]).unwrap();
        assert_eq!(aha.db, rctx.db);
        rctx.delete_namespace().unwrap();
        aha.delete_namespace().unwrap();
    }

    #[test]
    fn integration_test_nvtcache() -> RedisSinkResult<()> {
        let nvtcache = RedisCache::init(redis_url(), &[NameSpaceSelector::Free])?;

        let commands = [
            NVT(Version("202212101125".to_owned())),
            NVT(FileName("test.nasl".to_owned())),
            NVT(Tag(
                CreationDate,
                "2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)".to_owned(),
            )),
            NVT(Name("fancy name".to_owned())),
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
            NVT(ExcludedKeys(vec![
                "Settings/disable_cgi_scanning".to_owned(),
                "bla/bla".to_owned(),
            ])),
            NVT(RequiredUdpPorts(vec![
                "Services/udp/unknown".to_owned(),
                "17".to_owned(),
            ])),
            NVT(Reference(vec![
                NvtRef {
                    class: "cve".to_owned(),
                    id: "CVE-1999-0524".to_owned(),
                    text: None,
                },
                NvtRef {
                    class: "http://freshmeat.sourceforge.net/projects/eventh/".to_owned(),
                    id: "URL".to_owned(),
                    text: None,
                },
            ])),
            NVT(RequiredKeys(vec!["WMI/Apache/RootPath".to_owned()])),
            NVT(Oid("0.0.0.0.0.0.0.0.0.1".to_owned())),
            NVT(Preference(NvtPreference {
                id: Some(2),
                class: PreferenceType::Password,
                name: "Enable Password".to_owned(),
                default: "".to_owned(),
            })),
        ];
        for c in commands {
            nvtcache.dispatch("test.nasl", c).unwrap();
        }
        let get_commands = [
            (
                NVTKey::Version,
                vec![NVT(Version("202212101125".to_owned()))],
            ),
            (
                NVTKey::FileName,
                vec![NVT(FileName("test.nasl".to_owned()))],
            ),
            (NVTKey::Name, vec![NVT(Name("fancy name".to_owned()))]),
            (NVTKey::Category, vec![NVT(Category(Denial))]),
            (
                NVTKey::Tag,
                vec![NVT(Tag(CreationDate, "1366091481".to_owned()))],
            ),
            (
                NVTKey::Family,
                vec![NVT(Family("Denial of Service".to_owned()))],
            ),
            (
                NVTKey::Dependencies,
                vec![NVT(Dependencies(vec![
                    "ssh_detect.nasl".to_owned(),
                    "ssh2.nasl".to_owned(),
                ]))],
            ),
            (
                NVTKey::RequiredKeys,
                vec![NVT(RequiredKeys(vec!["WMI/Apache/RootPath".to_owned()]))],
            ),
            (
                NVTKey::MandatoryKeys,
                vec![NVT(MandatoryKeys(vec!["ssh/blubb/detected".to_owned()]))],
            ),
            (
                NVTKey::ExcludedKeys,
                vec![NVT(ExcludedKeys(vec![
                    "Settings/disable_cgi_scanning".to_owned(),
                    "bla/bla".to_owned(),
                ]))],
            ),
            (
                NVTKey::RequiredPorts,
                vec![NVT(RequiredPorts(vec![
                    "Services/ssh".to_owned(),
                    "22".to_owned(),
                ]))],
            ),
            (
                NVTKey::RequiredUdpPorts,
                vec![NVT(RequiredUdpPorts(vec![
                    "Services/udp/unknown".to_owned(),
                    "17".to_owned(),
                ]))],
            ),
            (
                NVTKey::Reference,
                vec![NVT(Reference(vec![
                    NvtRef {
                        class: "cve".to_owned(),
                        id: "CVE-1999-0524".to_owned(),
                        text: None,
                    },
                    NvtRef {
                        class: "URL".to_owned(),
                        id: "http://freshmeat.sourceforge.net/projects/eventh/".to_owned(),
                        text: None,
                    },
                ]))],
            ),
            (
                NVTKey::Preference,
                vec![NVT(Preference(NvtPreference {
                    id: Some(2),
                    class: PreferenceType::Password,
                    name: "Enable Password".to_owned(),
                    default: "".to_owned(),
                }))],
            ),
        ];
        // nvts can only be stored at the end of the run due to preferences and references being left sided
        // if the internal order of preferences and references doesn't matter we could store in the moment we have an oid
        nvtcache.on_exit().unwrap();
        for (cmd, expected) in get_commands {
            let actual = nvtcache
                .retrieve("0.0.0.0.0.0.0.0.0.1", sink::Retrieve::NVT(Some(cmd)))
                .unwrap();
            assert_eq!(actual, expected);
        }

        nvtcache.reset()?;

        Ok(())
    }
}
