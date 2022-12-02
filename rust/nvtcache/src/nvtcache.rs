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

pub struct RedisCache {
    cache: Arc<Mutex<RedisCtx>>,
    // The current redis implementation needs a complete NVT object to work with
    // due to the defined ordering.
    // Therefore it caches it until on exit is called.
    internal_cache: Arc<Mutex<Option<Nvt>>>,
}

const CACHE_KEY: &str = "nvticache";

/// Cache implementation.
///
/// We need a second level cache before redis due to NVT runs. In this case we need to have the complete data to get the ordering right.
/// This should be changed when there is new OSP frontend available.
impl RedisCache {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    /// While the plugin_path is given without the protocol infix.
    /// The reason is that while redis can be configured to use tcp the plugins must be available within the filesystem.
    pub fn init(redis_url: &str) -> RedisResult<RedisCache> {
        let rctx = RedisCtx::new(redis_url)?;

        Ok(RedisCache {
            cache: Arc::new(Mutex::new(rctx)),
            internal_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&self) -> RedisResult<()> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.delete_namespace()
    }

    fn store_nvt(&self, cache: &mut RedisCtx) -> RedisResult<()> {
        let may_nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
        if let Some(nvtc) = &*may_nvtc {
            cache.redis_add_nvt(nvtc)?;
        }
        // TODO add oid duplicate check on interpreter

        Ok(())
    }
}

impl From<DbError> for SinkError {
    fn from(_: DbError) -> Self {
        Self {}
    }
}

impl Sink for RedisCache {
    fn store(&self, _key: &str, scope: StoreType) -> Result<(), SinkError> {
        match scope {
            StoreType::NVT(field) => {
                let mut may_nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
                if may_nvtc.is_none() {
                    *may_nvtc = Some(Nvt::default());
                }
                if let Some(nvtc) = &mut *may_nvtc {
                    match field {
                        NVTField::Oid(oid) => nvtc.set_oid(oid),
                        NVTField::FileName(name) => nvtc.set_filename(name),
                        NVTField::Name(name) => nvtc.set_name(name),
                        NVTField::Tag(key, value) => nvtc.add_tag(key.as_ref().to_owned(), value),
                        NVTField::Dependencies(dependencies) => nvtc.set_dependencies(dependencies),
                        NVTField::RequiredKeys(rk) => nvtc.set_required_keys(rk),
                        NVTField::MandatoryKeys(mk) => nvtc.set_mandatory_keys(mk),
                        NVTField::ExcludedKeys(ek) => nvtc.set_excluded_keys(ek),
                        NVTField::RequiredPorts(rp) => nvtc.set_required_ports(rp),
                        NVTField::RequiredUdpPorts(rup) => nvtc.set_required_udp_ports(rup),
                        NVTField::Preference(pref) => nvtc.add_pref(pref),
                        NVTField::Category(cat) => nvtc.set_category(cat),
                        NVTField::Family(family) => nvtc.set_family(family),
                        NVTField::Reference(x) => nvtc.add_ref(x),
                        NVTField::NoOp => {
                            // script_version
                            // script_copyright
                            // are getting ignored. Although they're still being in NASL they have no functionality
                        }
                        NVTField::Version(version) => {
                            let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
                            cache.redis_set_key(CACHE_KEY, version)?;
                            return Ok(());
                        }
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
                        let mut result = vec![];
                        for tag in tags.split('|') {
                            let (key, value) = tag.rsplit_once('=').ok_or(SinkError {})?;
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
                                let (id, class) = r.rsplit_once(':').ok_or(SinkError {})?;

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
                    NVTKey::Version => {
                        let feed = cache.redis_key(CACHE_KEY)?;
                        Ok(vec![StoreType::NVT(NVTField::Version(feed))])
                    }
                },
                None => todo!(),
            },
        }
    }
}
