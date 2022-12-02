use sink::GetType;
use sink::NVTField;
use sink::NVTKey;
use sink::NvtRef;
use sink::Sink;
use sink::SinkError;
use sink::StoreType;
use sink::TagKey;
use sink::ACT;

use crate::dberror::DbError;
use crate::dberror::RedisResult;
use crate::nvt::*;
use crate::redisconnector::*;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::Mutex;

pub struct RedisNvtCache {
    cache: Arc<Mutex<RedisCtx>>,
    // The current redis implementation needs a complete NVT object to work with
    // due to the defined ordering.
    // Therefore it caches it until on exit is called.
    internal_cache: Arc<Mutex<Nvt>>,
}

const CACHE_KEY: &str = "nvticache";

/// NvtCache implementation.
impl RedisNvtCache {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    /// While the plugin_path is given without the protocol infix.
    /// The reason is that while redis can be configured to use tcp the plugins must be available within the filesystem.
    pub fn init(redis_url: &str) -> RedisResult<RedisNvtCache> {
        let rctx = RedisCtx::new(redis_url)?;

        Ok(RedisNvtCache {
            cache: Arc::new(Mutex::new(rctx)),
            internal_cache: Arc::new(Mutex::new(Nvt::default())),
        })
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&self) -> RedisResult<()> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.delete_namespace()
    }

    // TODO move that out of here

    /// Set the key nvtcache
    pub fn set_version(&self, feed_version: &str) -> RedisResult<()> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.redis_set_key(CACHE_KEY, feed_version)
    }

    /// Get the key nvtcache, which has the feed version
    pub fn get_version(&self) -> RedisResult<String> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.redis_key(CACHE_KEY)
    }

    /// Check if the nvtcache is uptodate, comparing the feed version
    /// in the filesystem (in plugin_feed_info.inc) and compare it
    /// with the version in the cache
    /// Return True if it is updated, False if outdated, Error otherwise.
    pub fn check_feed(&self, current: &str) -> RedisResult<bool> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let cached = cache.redis_key(CACHE_KEY)?;
        if cached == current {
            return Ok(true);
        }
        Ok(false)
    }
    // END TODO

    pub fn get_nvt_field(&self, oid: String, field: KbNvtPos) -> RedisResult<String> {
        let key = format!("nvt:{}", oid);
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let value = cache.lindex(&key, field)?;
        Ok(value)
    }

    pub fn get_nvt_filename(&self, oid: &str) -> RedisResult<String> {
        let key = format!("nvt:{}", oid);
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let filename = cache.lindex(&key, KbNvtPos::Filename)?;
        Ok(filename)
    }

    fn store_nvt(&self, cache: &mut RedisCtx) -> RedisResult<()> {
        let nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
        // TODO add oid duplicate check on interpreter

        cache.redis_add_nvt(nvtc.clone()).unwrap();

        Ok(())
    }
}

impl From<DbError> for SinkError {
    fn from(_: DbError) -> Self {
        Self {}
    }
}

impl Sink for RedisNvtCache {
    fn store(&self, _key: &str, scope: sink::StoreType) -> Result<(), sink::SinkError> {
        match scope {
            StoreType::NVT(field) => {
                let mut nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
                match field {
                    sink::NVTField::Oid(oid) => nvtc.set_oid(oid),
                    sink::NVTField::FileName(name) => nvtc.set_filename(name),
                    sink::NVTField::Name(name) => nvtc.set_name(name),
                    sink::NVTField::Tag(key, value) => nvtc.add_tag(key.as_ref().to_owned(), value),
                    sink::NVTField::Dependencies(dependencies) => {
                        nvtc.set_dependencies(dependencies)
                    }
                    sink::NVTField::RequiredKeys(rk) => nvtc.set_required_keys(rk),
                    sink::NVTField::MandatoryKeys(mk) => nvtc.set_mandatory_keys(mk),
                    sink::NVTField::ExcludedKeys(ek) => nvtc.set_excluded_keys(ek),
                    sink::NVTField::RequiredPorts(rp) => nvtc.set_required_ports(rp),
                    sink::NVTField::RequiredUdpPorts(rup) => nvtc.set_required_udp_ports(rup),
                    sink::NVTField::Preference(pref) => nvtc.add_pref(pref),
                    sink::NVTField::Category(cat) => nvtc.set_category(cat),
                    sink::NVTField::Family(family) => nvtc.set_family(family),
                    sink::NVTField::Reference(x) => nvtc.add_ref(x),
                    sink::NVTField::NoOp => {
                        // script_version
                        // script_copyright
                        // are getting ignored. Although they're still being in NASL they have no functionality
                    }
                }
                Ok(())
            }
        }
    }

    fn on_exit(&self) -> Result<(), sink::SinkError> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        self.store_nvt(cache.deref_mut())?;
        Ok(())
    }

    fn get(&self, key: &str, scope: sink::GetType) -> Result<Vec<StoreType>, SinkError> {
        let rkey = format!("nvt:{}", key);
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        let mut as_stringvec = |key: KbNvtPos| -> Result<Vec<String>, SinkError> {
            let dependencies = cache.lindex(&rkey, key)?;
            Ok(dependencies
                .split(',')
                .into_iter()
                .map(|s| s.to_owned())
                .collect())
        };
        match scope {
            GetType::NVT(nvt) => match nvt {
                Some(x) => match x {
                    NVTKey::Oid => Ok(vec![StoreType::NVT(sink::NVTField::Oid(key.to_owned()))]),
                    NVTKey::FileName => {
                        let strresult = cache.lindex(&rkey, KbNvtPos::Filename)?;
                        Ok(vec![StoreType::NVT(sink::NVTField::FileName(strresult))])
                    }
                    NVTKey::Name => {
                        let strresult = cache.lindex(&rkey, KbNvtPos::Name)?;
                        Ok(vec![StoreType::NVT(sink::NVTField::Name(strresult))])
                    }
                    NVTKey::Tag => {
                        let tags = cache.lindex(&rkey, KbNvtPos::Tags)?;
                        // thsore are references
                        //let cves = cache.lindex(&rkey, KbNvtPos::Cves)?;
                        //let bids = cache.lindex(&rkey, KbNvtPos::Bids)?;
                        //let xref = cache.lindex(&rkey, KbNvtPos::Xrefs)?;
                        let mut result = vec![];
                        for tag in tags.split('|') {
                            let (key, value) = {
                                let kv_pair: Vec<&str> = tag.split('=').collect();
                                if kv_pair.len() != 2 {
                                    return Err(SinkError {});
                                }
                                (kv_pair[0], kv_pair[1])
                            };
                            let key: TagKey = key.parse()?;
                            result.push(StoreType::NVT(NVTField::Tag(key, value.to_owned())));
                        }

                        Ok(result)
                    }
                    NVTKey::Dependencies => Ok(vec![StoreType::NVT(NVTField::Dependencies(
                        as_stringvec(KbNvtPos::Dependencies)?,
                    ))]),
                    NVTKey::RequiredKeys => Ok(vec![StoreType::NVT(NVTField::RequiredKeys(
                        as_stringvec(KbNvtPos::RequiredKeys)?,
                    ))]),
                    NVTKey::MandatoryKeys => Ok(vec![StoreType::NVT(NVTField::MandatoryKeys(
                        as_stringvec(KbNvtPos::MandatoryKeys)?,
                    ))]),
                    NVTKey::ExcludedKeys => Ok(vec![StoreType::NVT(NVTField::ExcludedKeys(
                        as_stringvec(KbNvtPos::ExcludedKeys)?,
                    ))]),
                    NVTKey::RequiredPorts => Ok(vec![StoreType::NVT(NVTField::RequiredPorts(
                        as_stringvec(KbNvtPos::RequiredPorts)?,
                    ))]),
                    NVTKey::RequiredUdpPorts => Ok(vec![StoreType::NVT(
                        NVTField::RequiredUdpPorts(as_stringvec(KbNvtPos::RequiredUDPPorts)?),
                    )]),
                    NVTKey::Preference => todo!(),
                    NVTKey::Reference => {
                        let cves = cache.lindex(&rkey, KbNvtPos::Cves)?;
                        let bids = cache.lindex(&rkey, KbNvtPos::Bids)?;
                        let xref = cache.lindex(&rkey, KbNvtPos::Xrefs)?;
                        let mut results = vec![];
                        if !cves.is_empty() {
                            results.push(StoreType::NVT(NVTField::Reference(NvtRef {
                                class: "cve".to_owned(),
                                id: cves,
                                text: None,
                            })))
                        }
                        if !bids.is_empty() {
                            for bi in bids.split(" ,") {
                                results.push(StoreType::NVT(NVTField::Reference(NvtRef {
                                    class: "bid".to_owned(),
                                    id: bi.to_owned(),
                                    text: None,
                                })))
                            }
                        }
                        if !xref.is_empty() {
                            for r in xref.split(" ,") {
                                let (id, class) =
                                    { r.rsplit_once(':').ok_or_else(|| SinkError {})? };

                                results.push(StoreType::NVT(NVTField::Reference(NvtRef {
                                    class: class.to_owned(),
                                    id: id.to_owned(),
                                    text: None,
                                })))
                            }
                        }
                        Ok(results)
                    }
                    NVTKey::Category => {
                        let numeric: ACT = match cache.lindex(&rkey, KbNvtPos::Category)?.parse() {
                            Ok(x) => x,
                            Err(_) => return Err(SinkError {}),
                        };
                        Ok(vec![StoreType::NVT(sink::NVTField::Category(numeric))])
                    }
                    NVTKey::Family => {
                        let strresult = cache.lindex(&rkey, KbNvtPos::Family)?;
                        Ok(vec![StoreType::NVT(sink::NVTField::Family(strresult))])
                    }
                    NVTKey::NoOp => Ok(vec![]),
                },
                None => todo!(),
            },
        }
    }
}
