// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::ops::DerefMut;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;

use crate::dberror::DbError;
use crate::dberror::RedisSinkResult;
use crate::nvt::Nvt;
use redis::*;
use sink::nvt::NvtPreference;
use sink::nvt::NvtRef;
use sink::nvt::PreferenceType;
use sink::Dispatch;
use sink::Retrieve;
use sink::Sink;
use sink::SinkError;

enum KbNvtPos {
    Filename,
    RequiredKeys,
    MandatoryKeys,
    ExcludedKeys,
    RequiredUDPPorts,
    RequiredPorts,
    Dependencies,
    Tags,
    Cves,
    Bids,
    Xrefs,
    Category,
    Family,
    Name,
}

impl TryFrom<sink::nvt::NVTKey> for KbNvtPos {
    type Error = SinkError;

    fn try_from(value: sink::nvt::NVTKey) -> Result<Self, Self::Error> {
        Ok(match value {
            sink::nvt::NVTKey::FileName => Self::Filename,
            sink::nvt::NVTKey::Name => Self::Name,
            sink::nvt::NVTKey::Dependencies => Self::Dependencies,
            sink::nvt::NVTKey::RequiredKeys => Self::RequiredKeys,
            sink::nvt::NVTKey::MandatoryKeys => Self::MandatoryKeys,
            sink::nvt::NVTKey::ExcludedKeys => Self::ExcludedKeys,
            sink::nvt::NVTKey::RequiredPorts => Self::RequiredPorts,
            sink::nvt::NVTKey::RequiredUdpPorts => Self::RequiredUDPPorts,
            sink::nvt::NVTKey::Category => Self::Category,
            sink::nvt::NVTKey::Family => Self::Family,
            // tags must also be handled manually due to differentiation
            _ => {
                return Err(SinkError::UnexpectedData(format!(
                    "{:?} is not a redis position and must be handled differently",
                    value
                )))
            }
        })
    }
}

pub struct RedisCtx {
    kb: Connection, //a redis connection
    db: u32,        // the name space
    maxdb: u32,     // max db index
    global_db_index: String,
}

#[derive(Debug, PartialEq, Eq)]
struct RedisValueHandler {
    v: String,
}

impl FromRedisValue for RedisValueHandler {
    fn from_redis_value(v: &Value) -> redis::RedisResult<RedisValueHandler> {
        match v {
            Value::Nil => Ok(RedisValueHandler { v: String::new() }),
            _ => {
                let new_var: String = from_redis_value(v).unwrap_or_default();
                Ok(RedisValueHandler { v: new_var })
            }
        }
    }
}

impl RedisCtx {
    /// Connect to the redis server and return a redis context object
    pub fn new(redis_socket: &str) -> RedisSinkResult<RedisCtx> {
        let client = redis::Client::open(redis_socket)?;
        let kb = client.get_connection()?;
        let global_db_index = "GVM.__GlobalDBIndex".to_string();
        let mut redisctx = RedisCtx {
            kb,
            db: 0,
            maxdb: 0,
            global_db_index,
        };
        let _kbi = redisctx.select_database()?;
        Ok(redisctx)
    }

    /// Get the max db index configured for the redis server instance
    fn max_db_index(&mut self) -> RedisSinkResult<u32> {
        if self.maxdb > 0 {
            return Ok(self.maxdb);
        }

        // Redis always replies about config with a vector
        // of 2 string ["databases", "Number"]
        // Therefore we convert the "Number" to uint32
        let (_, max_db) = Cmd::new()
            .arg("CONFIG")
            .arg("GET")
            .arg("databases")
            .query::<(String, u32)>(&mut self.kb)?;
        self.maxdb = max_db;
        Ok(max_db)
    }

    fn namespace(&mut self) -> RedisSinkResult<u32> {
        let db: u32 = self.db;
        Ok(db)
    }

    fn set_namespace(&mut self, db_index: u32) -> RedisSinkResult<()> {
        Cmd::new()
            .arg("SELECT")
            .arg(db_index.to_string())
            .query(&mut self.kb)?;

        self.db = db_index;
        Ok(())
    }

    fn try_database(&mut self, dbi: u32) -> RedisSinkResult<u32> {
        let ret = self.kb.hset_nx(&self.global_db_index, dbi, 1)?;
        Ok(ret)
    }

    fn select_database(&mut self) -> RedisSinkResult<u32> {
        let maxdb: u32 = self.max_db_index()?;
        let mut selected_db: u32 = 0;

        // Start always from 1. Namespace 0 is reserved
        //format self.global_db_index
        for i in 1..maxdb {
            let ret = self.try_database(i)?;
            if ret == 1 {
                selected_db = i;
                break;
            }
        }
        if selected_db > 0 {
            self.set_namespace(selected_db)?;
            return Ok(self.db);
        }
        Err(DbError::NoAvailDbErr(String::from(
            "Not possible to select a free db",
        )))
    }

    /// Delete an entry from the in-use namespace's list
    fn release_namespace(&mut self) -> RedisSinkResult<()> {
        // Get the current db index first, the one to be released
        let dbi = self.namespace()?;
        // Remove the entry from the hash list
        self.set_namespace(0)?;
        self.kb.hdel(&self.global_db_index, dbi)?;
        Ok(())
    }

    /// Delete all keys in the namespace and release the it
    pub fn delete_namespace(&mut self) -> RedisSinkResult<()> {
        Cmd::new().arg("FLUSHDB").query(&mut self.kb)?;
        self.release_namespace()?;
        Ok(())
    }
    //Wrapper function to avoid accessing kb member directly.
    pub fn set_value<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisSinkResult<()> {
        self.kb.set(key, val)?;
        Ok(())
    }

    pub fn value(&mut self, key: &str) -> RedisSinkResult<String> {
        let ret: RedisValueHandler = self.kb.get(key)?;
        Ok(ret.v)
    }

    fn lindex(&mut self, key: &str, index: isize) -> RedisSinkResult<String> {
        let ret: RedisValueHandler = self.kb.lindex(key, index)?;
        Ok(ret.v)
    }

    fn lrange(&mut self, ket: &str, from: isize, to: isize) -> RedisSinkResult<Vec<String>> {
        let ret: Vec<Value> = self.kb.lrange(ket, from, to)?;
        Ok(ret
            .iter()
            .map(|v| from_redis_value(v).unwrap_or_default())
            .collect())
    }

    fn tags_as_single_string(&self, tags: &[(String, String)]) -> String {
        let tag: Vec<String> = tags
            .iter()
            .map(|(key, val)| format!("{}={}", key, val))
            .collect();

        tag.iter().as_ref().join("|")
    }
    /// Add an NVT in the redis cache.
    ///
    /// The NVT metadata is stored in two different keys:

    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    pub(crate) fn redis_add_nvt(&mut self, nvt: &Nvt) -> RedisSinkResult<()> {
        let oid = nvt.oid();
        let name = nvt.name();
        // TODO verify, before it was concat without delimiter which seems wrong
        let required_keys = nvt.required_keys().join(",");
        let mandatory_keys = nvt.mandatory_keys().join(",");
        let excluded_keys = nvt.excluded_keys().join(",");
        let required_udp_ports = nvt.required_udp_ports().join(",");
        let required_ports = nvt.required_ports().join(",");
        let dependencies = nvt.dependencies().join(",");
        let tags = self.tags_as_single_string(nvt.tag());
        let category = nvt.category().to_string();
        let family = nvt.family();

        // Get the references
        let (cves, bids, xrefs) = nvt.refs();

        let key_name = format!("nvt:{}", oid);
        let values = [
            nvt.filename(),
            &required_keys,
            &mandatory_keys,
            &excluded_keys,
            &required_udp_ports,
            &required_ports,
            &dependencies,
            &tags,
            &cves,
            &bids,
            &xrefs,
            &category,
            family,
            name,
        ];

        self.kb.rpush(key_name, &values)?;

        // Add preferences
        let prefs = nvt.prefs();
        if !prefs.is_empty() {
            let key_name = format!("oid:{}prefs", oid);
            self.kb.lpush(key_name, prefs)?;
        }

        Ok(())
    }
}

/// Cache implementation.
///
/// This implementation is thread-safe as it stored the underlying RedisCtx within a lockable arc reference.
///
/// We need a second level cache before redis due to NVT runs.
/// In this case we need to wait until we get the OID so that we can build the key additionally
/// we need to have all references and preferences to respect the order to be downwards compatible.
/// This should be changed when there is new OSP frontend available.
pub struct RedisCache {
    cache: Arc<Mutex<RedisCtx>>,
    // The current redis implementation needs a complete NVT object to work with
    // due to the defined ordering.
    // Therefore it caches it until on exit is called.
    internal_cache: Arc<Mutex<Option<Nvt>>>,
}

const CACHE_KEY: &str = "nvticache";

impl RedisCache {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    pub fn init(redis_url: &str) -> RedisSinkResult<RedisCache> {
        let rctx = RedisCtx::new(redis_url)?;

        Ok(RedisCache {
            cache: Arc::new(Mutex::new(rctx)),
            internal_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&self) -> RedisSinkResult<()> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        cache.delete_namespace()
    }

    fn store_nvt(&self, cache: &mut RedisCtx) -> RedisSinkResult<()> {
        let may_nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
        if let Some(nvtc) = &*may_nvtc {
            cache.redis_add_nvt(nvtc)?;
        }
        // TODO add oid duplicate check on interpreter
        Ok(())
    }

    fn retrieve_nvt_key(
        &self,
        cache: &mut RedisCtx,
        oid: &str,
        key: sink::nvt::NVTKey,
    ) -> Result<Vec<Dispatch>, SinkError> {
        let rkey = format!("nvt:{}", oid);
        let mut as_stringvec = |key: KbNvtPos| -> Result<Vec<String>, SinkError> {
            let dependencies = cache.lindex(&rkey, key as isize)?;
            Ok(dependencies
                .split(',')
                .into_iter()
                .map(|s| s.to_owned())
                .collect())
        };
        match key {
            sink::nvt::NVTKey::Oid => Ok(vec![Dispatch::NVT(sink::nvt::NVTField::Oid(
                oid.to_owned(),
            ))]),
            sink::nvt::NVTKey::FileName => {
                let strresult = cache.lindex(&rkey, KbNvtPos::Filename as isize)?;
                Ok(vec![Dispatch::NVT(sink::nvt::NVTField::FileName(
                    strresult,
                ))])
            }
            sink::nvt::NVTKey::Name => {
                let strresult = cache.lindex(&rkey, KbNvtPos::Name as isize)?;
                Ok(vec![Dispatch::NVT(sink::nvt::NVTField::Name(strresult))])
            }
            sink::nvt::NVTKey::Tag => {
                let tags = cache.lindex(&rkey, KbNvtPos::Tags as isize)?;
                let mut result = vec![];
                for tag in tags.split('|') {
                    let (key, value) = tag
                        .rsplit_once('=')
                        .ok_or_else(|| SinkError::UnexpectedData(tag.to_owned()))?;
                    let key: sink::nvt::TagKey = key.parse()?;
                    result.push(Dispatch::NVT(sink::nvt::NVTField::Tag(
                        key,
                        value.to_owned(),
                    )));
                }
                Ok(result)
            }
            sink::nvt::NVTKey::Dependencies => Ok(vec![Dispatch::NVT(
                sink::nvt::NVTField::Dependencies(as_stringvec(KbNvtPos::Dependencies)?),
            )]),
            sink::nvt::NVTKey::RequiredKeys => Ok(vec![Dispatch::NVT(
                sink::nvt::NVTField::RequiredKeys(as_stringvec(KbNvtPos::RequiredKeys)?),
            )]),
            sink::nvt::NVTKey::MandatoryKeys => Ok(vec![Dispatch::NVT(
                sink::nvt::NVTField::MandatoryKeys(as_stringvec(KbNvtPos::MandatoryKeys)?),
            )]),
            sink::nvt::NVTKey::ExcludedKeys => Ok(vec![Dispatch::NVT(
                sink::nvt::NVTField::ExcludedKeys(as_stringvec(KbNvtPos::ExcludedKeys)?),
            )]),
            sink::nvt::NVTKey::RequiredPorts => Ok(vec![Dispatch::NVT(
                sink::nvt::NVTField::RequiredPorts(as_stringvec(KbNvtPos::RequiredPorts)?),
            )]),
            sink::nvt::NVTKey::RequiredUdpPorts => Ok(vec![Dispatch::NVT(
                sink::nvt::NVTField::RequiredUdpPorts(as_stringvec(KbNvtPos::RequiredUDPPorts)?),
            )]),
            sink::nvt::NVTKey::Preference => {
                let pkey = format!("oid:{}prefs", oid);
                let result = cache.lrange(&pkey, 0, -1)?;
                Ok(result
                    .iter()
                    .map(|s| {
                        let split: Vec<&str> = s.split(':').collect();
                        let id = match split[0].parse() {
                            Ok(v) => Some(v),
                            Err(_) => None,
                        };
                        let name = split[1];
                        let class = match PreferenceType::from_str(split[2]) {
                            Ok(v) => v,
                            Err(_) => PreferenceType::Entry,
                        };
                        let default = split[3];
                        Dispatch::NVT(sink::nvt::NVTField::Preference(NvtPreference {
                            id,
                            class,
                            default: default.to_owned(),
                            name: name.to_owned(),
                        }))
                    })
                    .collect())
            }
            sink::nvt::NVTKey::Reference => {
                let cves = cache.lindex(&rkey, KbNvtPos::Cves as isize)?;
                let bids = cache.lindex(&rkey, KbNvtPos::Bids as isize)?;
                let xref = cache.lindex(&rkey, KbNvtPos::Xrefs as isize)?;
                let mut results = vec![];
                if !cves.is_empty() {
                    results.push(Dispatch::NVT(sink::nvt::NVTField::Reference(NvtRef {
                        class: "cve".to_owned(),
                        id: cves,
                        text: None,
                    })))
                }
                if !bids.is_empty() {
                    for bi in bids.split(" ,") {
                        results.push(Dispatch::NVT(sink::nvt::NVTField::Reference(NvtRef {
                            class: "bid".to_owned(),
                            id: bi.to_owned(),
                            text: None,
                        })))
                    }
                }
                if !xref.is_empty() {
                    for r in xref.split(" ,") {
                        let (id, class) = r
                            .rsplit_once(':')
                            .ok_or_else(|| SinkError::UnexpectedData(r.to_owned()))?;

                        results.push(Dispatch::NVT(sink::nvt::NVTField::Reference(NvtRef {
                            class: class.to_owned(),
                            id: id.to_owned(),
                            text: None,
                        })))
                    }
                }
                Ok(results)
            }
            sink::nvt::NVTKey::Category => {
                let act: sink::nvt::ACT =
                    cache.lindex(&rkey, KbNvtPos::Category as isize)?.parse()?;
                Ok(vec![Dispatch::NVT(sink::nvt::NVTField::Category(act))])
            }
            sink::nvt::NVTKey::Family => {
                let strresult = cache.lindex(&rkey, KbNvtPos::Family as isize)?;
                Ok(vec![Dispatch::NVT(sink::nvt::NVTField::Family(strresult))])
            }
            sink::nvt::NVTKey::NoOp => Ok(vec![]),
            sink::nvt::NVTKey::Version => {
                let feed = cache.value(CACHE_KEY)?;
                Ok(vec![Dispatch::NVT(sink::nvt::NVTField::Version(feed))])
            }
        }
    }
}

impl Sink for RedisCache {
    fn dispatch(&self, _key: &str, scope: Dispatch) -> Result<(), SinkError> {
        match scope {
            Dispatch::NVT(field) => {
                let mut may_nvtc = Arc::as_ref(&self.internal_cache).lock().unwrap();
                if may_nvtc.is_none() {
                    *may_nvtc = Some(Nvt::default());
                }
                if let Some(nvtc) = &mut *may_nvtc {
                    match field {
                        sink::nvt::NVTField::Oid(oid) => nvtc.set_oid(oid),
                        sink::nvt::NVTField::FileName(name) => nvtc.set_filename(name),
                        sink::nvt::NVTField::Name(name) => nvtc.set_name(name),
                        sink::nvt::NVTField::Tag(key, value) => {
                            nvtc.add_tag(key.as_ref().to_owned(), value)
                        }
                        sink::nvt::NVTField::Dependencies(dependencies) => {
                            nvtc.set_dependencies(dependencies)
                        }
                        sink::nvt::NVTField::RequiredKeys(rk) => nvtc.set_required_keys(rk),
                        sink::nvt::NVTField::MandatoryKeys(mk) => nvtc.set_mandatory_keys(mk),
                        sink::nvt::NVTField::ExcludedKeys(ek) => nvtc.set_excluded_keys(ek),
                        sink::nvt::NVTField::RequiredPorts(rp) => nvtc.set_required_ports(rp),
                        sink::nvt::NVTField::RequiredUdpPorts(rup) => {
                            nvtc.set_required_udp_ports(rup)
                        }
                        sink::nvt::NVTField::Preference(pref) => nvtc.add_pref(pref),
                        sink::nvt::NVTField::Category(cat) => nvtc.set_category(cat),
                        sink::nvt::NVTField::Family(family) => nvtc.set_family(family),
                        sink::nvt::NVTField::Reference(x) => nvtc.add_ref(x),
                        sink::nvt::NVTField::NoOp => {
                            // script_version
                            // script_copyright
                            // are getting ignored. Although they're still being in NASL they have no functionality
                        }
                        sink::nvt::NVTField::Version(version) => {
                            let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
                            cache.set_value(CACHE_KEY, version)?;
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

    fn retrieve(&self, key: &str, scope: sink::Retrieve) -> Result<Vec<Dispatch>, SinkError> {
        let mut cache = Arc::as_ref(&self.cache).lock().unwrap();
        match scope {
            Retrieve::NVT(nvt) => match nvt {
                Some(x) => self.retrieve_nvt_key(&mut cache, key, x),
                None => {
                    let fields = [
                        sink::nvt::NVTKey::Oid,
                        sink::nvt::NVTKey::FileName,
                        sink::nvt::NVTKey::Version,
                        sink::nvt::NVTKey::Name,
                        sink::nvt::NVTKey::Tag,
                        sink::nvt::NVTKey::Dependencies,
                        sink::nvt::NVTKey::RequiredKeys,
                        sink::nvt::NVTKey::MandatoryKeys,
                        sink::nvt::NVTKey::ExcludedKeys,
                        sink::nvt::NVTKey::RequiredPorts,
                        sink::nvt::NVTKey::RequiredUdpPorts,
                        sink::nvt::NVTKey::Preference,
                        sink::nvt::NVTKey::Reference,
                        sink::nvt::NVTKey::Category,
                        sink::nvt::NVTKey::Family,
                    ];
                    let mut result: Vec<Dispatch> = vec![];
                    for k in fields {
                        let mut single_field_result = self.retrieve_nvt_key(&mut cache, key, k)?;
                        result.append(&mut single_field_result);
                    }
                    Ok(result)
                }
            },
        }
    }
}
