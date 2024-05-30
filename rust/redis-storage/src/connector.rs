// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::BTreeMap;
use std::fmt::Debug;

use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::usize;

use crate::dberror::DbError;
use crate::dberror::RedisStorageResult;
use itertools::Itertools;
use redis::*;

use storage::item::Nvt;
use storage::item::NvtPreference;
use storage::item::NvtRef;
use storage::item::TagKey;
use storage::item::TagValue;
use storage::Kb;
use storage::NotusAdvisory;

use storage::StorageError;

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

// impl TryFrom<storage::item::NVTKey> for KbNvtPos {
//     type Error = StorageError;
//
//     fn try_from(value: storage::item::NVTKey) -> Result<Self, Self::Error> {
//         Ok(match value {
//             storage::item::NVTKey::FileName => Self::Filename,
//             storage::item::NVTKey::Name => Self::Name,
//             storage::item::NVTKey::Dependencies => Self::Dependencies,
//             storage::item::NVTKey::RequiredKeys => Self::RequiredKeys,
//             storage::item::NVTKey::MandatoryKeys => Self::MandatoryKeys,
//             storage::item::NVTKey::ExcludedKeys => Self::ExcludedKeys,
//             storage::item::NVTKey::RequiredPorts => Self::RequiredPorts,
//             storage::item::NVTKey::RequiredUdpPorts => Self::RequiredUDPPorts,
//             storage::item::NVTKey::Category => Self::Category,
//             storage::item::NVTKey::Family => Self::Family,
//             // tags must also be handled manually due to differentiation
//             _ => {
//                 return Err(StorageError::UnexpectedData(format!(
//                     "{value:?} is not a redis position and must be handled differently"
//                 )))
//             }
//         })
//     }
// }
#[derive(Default)]
pub struct RedisCtx {
    kb: Option<Connection>, //a redis connection
    pub db: u32,            // the name space
}

impl Debug for RedisCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redis connection. Db {}", self.db)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RedisVectorHandler {
    v: Vec<String>,
}

impl FromRedisValue for RedisVectorHandler {
    fn from_redis_value(v: &Value) -> redis::RedisResult<RedisVectorHandler> {
        match v {
            Value::Nil => Ok(RedisVectorHandler { v: Vec::new() }),
            _ => {
                let new_var: String = from_redis_value(v).unwrap_or_default();
                let nv = vec![new_var];
                Ok(RedisVectorHandler { v: nv })
            }
        }
    }
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

#[derive(Debug, PartialEq, Eq)]
/// Defines how the RedixCtx should select the namespace
pub enum NameSpaceSelector {
    /// Defines to use a fix DB
    Fix(u32),
    /// Next free
    Free,
    /// Uses a DB that contains this key
    Key(&'static str),
}

const CACHE_KEY: &str = "nvticache";
const NOTUS_KEY: &str = "notuscache";
const DB_INDEX: &str = "GVM.__GlobalDBIndex";

impl NameSpaceSelector {
    fn max_db(kb: &mut redis::Connection) -> RedisStorageResult<u32> {
        Cmd::new()
            .arg("CONFIG")
            .arg("GET")
            .arg("databases")
            .query::<(String, u32)>(kb)
            .map(|(_, max_db)| max_db)
            .map_err(|e| e.into())
    }

    fn select_namespace(kb: &mut redis::Connection, idx: u32) -> RedisStorageResult<()> {
        Cmd::new()
            .arg("SELECT")
            .arg(idx)
            .query(kb)
            .map_err(|e| e.into())
    }

    fn select(&self, kb: &mut redis::Connection) -> RedisStorageResult<u32> {
        let max_db = Self::max_db(kb)?;
        match self {
            NameSpaceSelector::Fix(dbi) => {
                Self::select_namespace(kb, *dbi)?;
                Ok(*dbi)
            }
            NameSpaceSelector::Free => {
                Self::select_namespace(kb, 0)?;
                for dbi in 1..max_db {
                    match kb.hset_nx(DB_INDEX, dbi, 1) {
                        Ok(1) => {
                            Self::select_namespace(kb, dbi)?;
                            return Ok(dbi);
                        }
                        Ok(_) => {}
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(DbError::NoAvailDbErr)
            }
            NameSpaceSelector::Key(key) => {
                for dbi in 1..max_db {
                    Self::select_namespace(kb, dbi)?;
                    match kb.exists(key) {
                        Ok(1) => return Ok(dbi),
                        Ok(_) => {}
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(DbError::NoAvailDbErr)
            }
        }
    }
}

/// Default selector for a feed-update run
pub const FEEDUPDATE_SELECTOR: &[NameSpaceSelector] =
    &[NameSpaceSelector::Key(CACHE_KEY), NameSpaceSelector::Free];
pub const NOTUSUPDATE_SELECTOR: &[NameSpaceSelector] =
    &[NameSpaceSelector::Key(NOTUS_KEY), NameSpaceSelector::Free];

pub trait RedisWrapper {
    fn rpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()>;
    fn lpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()>;
    fn lindex(&mut self, key: &str, index: isize) -> RedisStorageResult<String>;
    fn lrange(&mut self, key: &str, start: isize, end: isize) -> RedisStorageResult<Vec<String>>;
    fn keys(&mut self, pattern: &str) -> RedisStorageResult<Vec<String>>;
    fn pop(&mut self, pattern: &str) -> RedisStorageResult<Vec<String>>;
}

impl RedisWrapper for RedisCtx {
    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn rpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
        self.kb
            .as_mut()
            .expect("Valid redis connection")
            .rpush(key, val)
            .map_err(|e| e.into())
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
        self.kb
            .as_mut()
            .expect("Valid redis connection")
            .lpush(key, val)
            .map_err(|e| e.into())
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lindex(&mut self, key: &str, index: isize) -> RedisStorageResult<String> {
        let ret: RedisValueHandler = self
            .kb
            .as_mut()
            .expect("Valid redis connection")
            .lindex(key, index)?;
        Ok(ret.v)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lrange(&mut self, key: &str, start: isize, end: isize) -> RedisStorageResult<Vec<String>> {
        let ret = self
            .kb
            .as_mut()
            .expect("Valid redis connection")
            .lrange(key, start, end)?;
        Ok(ret)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn keys(&mut self, pattern: &str) -> RedisStorageResult<Vec<String>> {
        let ret: Vec<String> = self
            .kb
            .as_mut()
            .expect("Valid redis connection")
            .keys(pattern)?;
        Ok(ret)
    }

    fn pop(&mut self, key: &str) -> RedisStorageResult<Vec<String>> {
        let ret: (Vec<String>,) = redis::pipe()
            .cmd("LRANGE")
            .arg(key)
            .arg("0")
            .arg("-1")
            .cmd("DEL")
            .arg(key)
            .ignore()
            .query(&mut self.kb.as_mut().unwrap())
            .unwrap();
        // Since items are lpushed, the returned vector must be reversed to keep the order.
        let mut status = ret.0;
        status.reverse();

        Ok(status)
    }
}

pub trait RedisAddAdvisory: RedisWrapper {
    /// Add an NVT in the redis cache.
    ///
    /// The NVT metadata is stored in two different keys:

    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    fn redis_add_advisory(
        &mut self,
        _: &str,
        adv: Option<NotusAdvisory>,
    ) -> RedisStorageResult<()> {
        match adv {
            Some(data) => {
                let key = format!("internal/notus/advisories/{}", &data.adv.oid);
                let value = models::Vulnerability::from(data);
                let value = serde_json::to_string(&value)
                    .map_err(|e| DbError::Unknown(format!("Serialization error: {e}")))?;
                self.rpush(&key, value)?;
            }
            None => self.rpush(NOTUS_KEY, "1".to_string())?,
        };
        Ok(())
    }
}

impl RedisAddAdvisory for RedisCtx {}

pub trait RedisGetNvt: RedisWrapper {
    #[inline(always)]
    fn get_refs(bids: &str, cves: &str, xrefs: &str) -> Vec<NvtRef> {
        let f = |x: &str| match x.split_once(':') {
            Some((a, b)) => NvtRef::from((a, b)),
            None => NvtRef::from(("", "")),
        };
        let mut bid_refs: Vec<NvtRef> =
            bids.split(", ").map(|r| NvtRef::from(("bid", r))).collect();
        let mut cve_refs: Vec<NvtRef> =
            cves.split(", ").map(|r| NvtRef::from(("cve", r))).collect();
        let mut xrefs_refs = xrefs.split(", ").map(f).collect();

        let mut refs: Vec<NvtRef> = Vec::new();
        refs.append(&mut bid_refs);
        refs.append(&mut cve_refs);
        refs.append(&mut xrefs_refs);
        refs
    }

    #[inline(always)]
    fn get_prefs(&mut self, oid: &str) -> RedisStorageResult<Vec<NvtPreference>> {
        let keyname = format!("oid:{}:prefs", oid);
        let mut prefs_list = self.lrange(&keyname, 0, -1)?;
        let mut prefs: Vec<NvtPreference> = Vec::new();
        for p in prefs_list.iter_mut() {
            if let Some(sp) = p
                .splitn(4, "|||")
                .collect_tuple::<(&str, &str, &str, &str)>()
            {
                prefs.push(NvtPreference::from(sp));
            }
        }
        Ok(prefs)
    }

    #[inline(always)]
    fn get_tags(tags: &str) -> BTreeMap<TagKey, TagValue> {
        let mut tag_map = BTreeMap::new();

        let tag_list = tags.split('|').map(|x| {
            x.splitn(2, '=')
                .collect_tuple::<(&str, &str)>()
                .unwrap_or_default()
        });

        for (k, v) in tag_list.into_iter() {
            if let Ok(tk) = TagKey::from_str(k) {
                tag_map.insert(tk, TagValue::from(v));
            }
        }

        tag_map
    }

    fn redis_get_advisory(&mut self, oid: &str) -> RedisStorageResult<Option<Nvt>> {
        let keyname = format!("internal/notus/advisories/{}", oid);
        let nvt_data = self.lindex(&keyname, 0)?;
        if nvt_data.is_empty() {
            return Ok(None);
        }

        if let Ok(adv) = serde_json::from_str::<models::Vulnerability>(&nvt_data) {
            Ok(Some(Nvt::from((oid, adv))))
        } else {
            Ok(None)
        }
    }
    /// Nvt metadata is stored under two different keys
    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    fn redis_get_vt(&mut self, oid: &str) -> RedisStorageResult<Option<Nvt>> {
        let keyname = format!("nvt:{}", oid);
        let nvt_data = self.lrange(&keyname, 0, -1)?;

        if nvt_data.is_empty() {
            return Ok(None);
        }

        let nvt = Nvt {
            oid: oid.to_string(),
            name: nvt_data[KbNvtPos::Name as usize].clone(),
            filename: nvt_data[KbNvtPos::Filename as usize].clone(),
            tag: Self::get_tags(&nvt_data[KbNvtPos::Tags as usize].clone()),
            dependencies: nvt_data[KbNvtPos::Dependencies as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            required_keys: nvt_data[KbNvtPos::RequiredKeys as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            mandatory_keys: nvt_data[KbNvtPos::MandatoryKeys as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            excluded_keys: nvt_data[KbNvtPos::ExcludedKeys as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            required_ports: nvt_data[KbNvtPos::RequiredPorts as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            required_udp_ports: nvt_data[KbNvtPos::RequiredUDPPorts as usize]
                .split(',')
                .map(|x| x.to_string())
                .collect(),
            references: Self::get_refs(
                &nvt_data[KbNvtPos::Bids as usize].clone(),
                &nvt_data[KbNvtPos::Cves as usize].clone(),
                &nvt_data[KbNvtPos::Xrefs as usize].clone(),
            ),
            preferences: Self::get_prefs(self, oid)?,
            category: {
                match storage::item::ACT::from_str(&nvt_data[KbNvtPos::Category as usize]) {
                    Ok(c) => c,
                    Err(_) => return Err(DbError::Unknown("Invalid nvt category".to_string())),
                }
            },
            family: nvt_data[KbNvtPos::Family as usize].clone(),
        };

        Ok(Some(nvt))
    }
}

impl RedisGetNvt for RedisCtx {}

pub trait RedisAddNvt: RedisWrapper {
    /// Get References. It returns a tuple of three strings
    /// Each string is a references type, and each string
    /// can contain a list of references of the same type.
    /// The string contains in the following types:
    /// (cve_types, bid_types, other_types)
    /// cve and bid strings are CSC strings containing only
    /// "id, id, ...", while other custom types includes the type
    /// and the string is in the format "type:id, type:id, ..."
    #[inline(always)]
    fn refs(references: &[NvtRef]) -> (String, String, String) {
        let (bids, cves, xrefs): (Vec<String>, Vec<String>, Vec<String>) =
            references
                .iter()
                .fold((vec![], vec![], vec![]), |(bids, cves, xrefs), b| {
                    match b.class() {
                        "bid" => {
                            let mut new_bids = bids;
                            new_bids.push(b.id().to_string());
                            (new_bids, cves, xrefs)
                        }
                        "cve" => {
                            let mut new_cves = cves;
                            new_cves.push(b.id().to_string());
                            (bids, new_cves, xrefs)
                        }
                        _ => {
                            let mut new_xref: Vec<String> = xrefs;
                            new_xref.push(format!("{}:{}", b.id(), b.class()));
                            (bids, cves, new_xref)
                        }
                    }
                });

        // Some references include a comma. Therefore the refs separator is ", ".
        // The string ", " is not accepted as reference value, since it will misunderstood
        // as ref separator.

        return (
            cves.iter().as_ref().join(", "),
            bids.iter().as_ref().join(", "),
            xrefs.iter().as_ref().join(", "),
        );
    }

    /// Transforms prefs to string representation {id}:{name}:{id}:{default} so that it can be stored into redis
    #[inline(always)]
    fn prefs(preferences: &[NvtPreference]) -> Vec<String> {
        let mut prefs = Vec::from(preferences);
        prefs.sort_by(|a, b| b.id.unwrap_or_default().cmp(&a.id.unwrap_or_default()));
        let results: Vec<String> = prefs
            .iter()
            .map(|pref| {
                format!(
                    "{}|||{}|||{}|||{}",
                    pref.id().unwrap_or_default(),
                    pref.name(),
                    pref.class().as_ref(),
                    pref.default()
                )
            })
            .collect();
        results
    }

    /// Add an NVT in the redis cache.
    ///
    /// The NVT metadata is stored in two different keys:

    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    fn redis_add_nvt(&mut self, nvt: Nvt) -> RedisStorageResult<()> {
        let oid = nvt.oid;
        let name = nvt.name;
        let required_keys = nvt.required_keys.join(", ");
        let mandatory_keys = nvt.mandatory_keys.join(", ");
        let excluded_keys = nvt.excluded_keys.join(", ");
        let required_udp_ports = nvt.required_udp_ports.join(", ");
        let required_ports = nvt.required_ports.join(", ");
        let dependencies = nvt.dependencies.join(", ");
        let tags = nvt
            .tag
            .iter()
            .map(|(key, val)| format!("{key}={val}"))
            .collect::<Vec<String>>()
            .join("|");
        let category = (nvt.category as i64).to_string();
        let family = nvt.family;
        let filename = nvt.filename;

        // Get the references
        let (cves, bids, xrefs) = Self::refs(&nvt.references);

        let key_name = format!("nvt:{oid}");
        let values = [
            &filename,
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
            &family,
            &name,
        ];
        self.rpush(&key_name, &values)?;

        // Add preferences
        let prefs = Self::prefs(&nvt.preferences);
        if !prefs.is_empty() {
            let key_name = format!("oid:{oid}:prefs");
            self.lpush(&key_name, prefs)?;
            //self.kb.lpush(&key_name, prefs)?;
        }

        // Stores the OID under the filename key. This key is currently used
        // for the dependency autoload, where the filename is used to fetch the OID.
        //
        // TODO: since openvas get the oid by position and it is stored in the second position,
        // for backward compatibility a dummy item (it is the plugin's upload timestamp)
        // under the filename key is added.
        // Once openvas is no longer used, the dummy item can be removed.
        let key_name = format!("filename:{filename}");
        self.rpush(&key_name, &["1", &oid])?;
        Ok(())
    }
}

impl RedisAddNvt for RedisCtx {}

impl RedisCtx {
    pub fn open(address: &str, selector: &[NameSpaceSelector]) -> RedisStorageResult<Self> {
        let client = redis::Client::open(address)?;

        let mut kb = client.get_connection()?;
        for s in selector {
            match s.select(&mut kb) {
                Ok(x) => {
                    return Ok(RedisCtx {
                        kb: Some(kb),
                        db: x,
                    })
                }
                Err(DbError::NoAvailDbErr) => {}
                Err(x) => return Err(x),
            }
        }
        Err(DbError::NoAvailDbErr)
    }

    /// Delete an entry from the in-use namespace's list
    fn release_namespace(&mut self) -> RedisStorageResult<()> {
        // Remove the entry from the in-use list and return to the original namespace
        redis::pipe()
            .cmd("SELECT")
            .arg("0")
            .cmd("HDEL")
            .arg(DB_INDEX)
            .arg(self.db)
            .cmd("SELECT")
            .arg(self.db)
            .ignore()
            .query(&mut self.kb.as_mut().expect("Valid redis connection"))?;
        Ok(())
    }

    /// Delete all keys in the namespace and release the it
    pub fn delete_namespace(&mut self) -> RedisStorageResult<()> {
        Cmd::new()
            .arg("FLUSHDB")
            .query(&mut self.kb.as_mut().expect("Valid redis connection"))?;
        self.release_namespace()?;
        Ok(())
    }

    /// Clean up the namespace.
    pub fn flush_namespace(&mut self) -> RedisStorageResult<()> {
        Cmd::new()
            .arg("FLUSHDB")
            .query(&mut self.kb.as_mut().expect("Valid redis connection"))?;
        Ok(())
    }

    //Wrapper function to avoid accessing kb member directly.
    pub fn set_value<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
        self.kb
            .as_mut()
            .expect("Valid redis connection")
            .set(key, val)?;
        Ok(())
    }

    pub fn value(&mut self, key: &str) -> RedisStorageResult<String> {
        let ret: RedisValueHandler = self.kb.as_mut().expect("Valid redis connection").get(key)?;
        Ok(ret.v)
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
#[derive(Debug, Default)]
pub struct CacheDispatcher<R>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    unfinished_vt: Arc<RwLock<Option<Nvt>>>,
    cache: Arc<Mutex<R>>,
    underlying_storage: storage::DefaultDispatcher,
}

impl CacheDispatcher<RedisCtx> {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    pub fn init(
        redis_url: &str,
        selector: &[NameSpaceSelector],
    ) -> RedisStorageResult<CacheDispatcher<RedisCtx>> {
        let rctx = RedisCtx::open(redis_url, selector)?;

        Ok(CacheDispatcher {
            unfinished_vt: Default::default(),
            cache: Arc::new(Mutex::new(rctx)),
            underlying_storage: Default::default(),
        })
    }

    /// Creates a dispatcher to be used to update the feed for a ospd service
    ///
    /// Initializes a redis cache based on the given selecter and url and clears the namespace
    /// before returning the underlying cache as a Dispatcher.
    pub fn as_dispatcher(
        redis_url: &str,
        selector: &[NameSpaceSelector],
    ) -> Result<impl storage::Storage, StorageError> {
        let cache = Self::init(redis_url, selector)?;
        cache.flushdb()?;
        Ok(cache)
        //Ok(PerItemDispatcher::new(cache))
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&self) -> RedisStorageResult<()> {
        let mut cache = Arc::as_ref(&self.cache)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;
        cache.delete_namespace()
    }

    /// Reset the NVT Cache. Do not release the namespace. Only ensure it is clean
    pub fn flushdb(&self) -> RedisStorageResult<()> {
        let mut cache = Arc::as_ref(&self.cache)
            .lock()
            .map_err(|e| DbError::SystemError(format!("{e:?}")))?;
        cache.flush_namespace()
    }
}

impl<S> storage::Storage for CacheDispatcher<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    fn cache_nvt_field(
        &self,
        filename: &str,
        field: storage::item::NVTField,
    ) -> Result<(), StorageError> {
        let mut data = self.unfinished_vt.as_ref().write()?;
        if let Some(vt) = data.as_mut() {
            if let Err(version) = vt.set_from_field(field) {
                let mut cache = Arc::as_ref(&self.cache).lock()?;
                cache.rpush(CACHE_KEY, &[&version])?;
            }
        } else {
            let mut nvt = storage::item::Nvt {
                filename: filename.to_string(),
                ..Default::default()
            };
            nvt.set_from_field(field);
            *data = Some(nvt);
        }
        Ok(())
    }

    fn description_script_finished(&self) -> Result<(), StorageError> {
        let mut data = self.unfinished_vt.as_ref().write()?;
        if let Some(vt) = data.as_ref() {
            self.store_vt(vt.clone())?;
            *data = None;
        }
        Ok(())
    }

    fn store_vt(&self, vt: storage::item::Nvt) -> Result<(), StorageError> {
        let mut cache = Arc::as_ref(&self.cache).lock()?;
        cache.redis_add_nvt(vt).map_err(|e| e.into())
    }

    fn vts_by_fields(
        &self,
        _keys: Vec<storage::item::NVTField>,
    ) -> Result<impl Iterator<Item = storage::item::Nvt>, StorageError> {
        Ok(vec![].into_iter())
    }

    fn all_vts(&self) -> Result<impl Iterator<Item = storage::item::Nvt>, StorageError> {
        Ok(vec![].into_iter())
    }

    fn store_notus_advisory(&self, advistory: NotusAdvisory) -> Result<(), StorageError> {
        let mut cache = Arc::as_ref(&self.cache).lock()?;
        cache
            .redis_add_advisory("", Some(advistory))
            .map_err(|e| e.into())
    }

    fn store_kb(&self, scan_id: &str, kb: Kb) -> Result<(), StorageError> {
        self.underlying_storage.store_kb(scan_id, kb)
    }

    fn get_kb(
        &self,
        scan_id: &str,
        key: &storage::KbKey,
    ) -> Result<impl Iterator<Item = Kb>, StorageError> {
        self.underlying_storage.get_kb(scan_id, key)
    }

    fn has_kb(&self, scan_id: &str, key: &storage::KbKey) -> Result<bool, StorageError> {
        self.underlying_storage.has_kb(scan_id, key)
    }

    fn scan_finished(&self, scan_id: &str) -> Result<(), StorageError> {
        self.underlying_storage.scan_finished(scan_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, Sender, TryRecvError};
    use std::sync::{Arc, Mutex};

    use storage::item::{NvtPreference, NvtRef, PreferenceType, TagKey, TagValue, ACT};

    use super::{CacheDispatcher, RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisWrapper};

    #[derive(Clone)]
    struct FakeRedis {
        sender: Sender<(String, Vec<Vec<u8>>)>,
    }
    impl RedisWrapper for FakeRedis {
        fn rpush<T: redis::ToRedisArgs>(
            &mut self,
            key: &str,
            val: T,
        ) -> crate::dberror::RedisStorageResult<()> {
            self.sender
                .send((key.to_owned(), val.to_redis_args()))
                .unwrap();
            Ok(())
        }

        fn lpush<T: redis::ToRedisArgs>(
            &mut self,
            key: &str,
            val: T,
        ) -> crate::dberror::RedisStorageResult<()> {
            self.sender
                .send((key.to_owned(), val.to_redis_args()))
                .unwrap();
            Ok(())
        }
        fn lindex(&mut self, _: &str, _: isize) -> crate::dberror::RedisStorageResult<String> {
            Ok(String::new())
        }

        fn keys(&mut self, _: &str) -> crate::dberror::RedisStorageResult<Vec<String>> {
            Ok(Vec::new())
        }
        fn pop(&mut self, _: &str) -> crate::dberror::RedisStorageResult<Vec<String>> {
            Ok(Vec::new())
        }

        fn lrange(
            &mut self,
            _: &str,
            _: isize,
            _: isize,
        ) -> crate::dberror::RedisStorageResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    impl RedisAddNvt for FakeRedis {}
    impl RedisAddAdvisory for FakeRedis {}
    impl RedisGetNvt for FakeRedis {}

    use storage::item::NVTField::*;
    #[test]
    fn transform_nvt() {
        let commands = [
            Version("202212101125".to_owned()),
            Tag(TagKey::CreationDate, TagValue::Number(23)),
            Name("fancy name".to_owned()),
            Category(ACT::Denial),
            Family("Denial of Service".to_owned()),
            Dependencies(vec!["ssh_detect.nasl".to_owned(), "ssh2.nasl".to_owned()]),
            RequiredPorts(vec!["Services/ssh".to_owned(), "22".to_owned()]),
            MandatoryKeys(vec!["ssh/blubb/detected".to_owned()]),
            ExcludedKeys(vec![
                "Settings/disable_cgi_scanning".to_owned(),
                "bla/bla".to_owned(),
            ]),
            RequiredUdpPorts(vec!["Services/udp/unknown".to_owned(), "17".to_owned()]),
            Reference(vec![
                NvtRef {
                    class: "cve".to_owned(),
                    id: "CVE-1999-0524".to_owned(),
                },
                NvtRef {
                    class: "http://freshmeat.sourceforge.net/projects/eventh/".to_owned(),
                    id: "URL".to_owned(),
                },
            ]),
            RequiredKeys(vec!["WMI/Apache/RootPath".to_owned()]),
            Oid("0.0.0.0.0.0.0.0.0.1".to_owned()),
            FileName("test.nasl".to_owned()),
            Preference(NvtPreference {
                id: Some(2),
                class: PreferenceType::Password,
                name: "Enable Password".to_owned(),
                default: "".to_owned(),
            }),
        ];
        let (sender, rx) = mpsc::channel();
        let fr = FakeRedis { sender };
        let cache = Arc::new(Mutex::new(fr));
        let rcache = CacheDispatcher {
            cache,
            unfinished_vt: Default::default(),
            underlying_storage: Default::default(),
        };
        let dispatcher = rcache;
        use storage::Storage;
        for c in commands {
            dispatcher.cache_nvt_field("test.nasl", c);
        }
        dispatcher.description_script_finished().unwrap();
        let mut results = 0;
        loop {
            match rx.try_recv() {
                Ok((key, values)) => {
                    results += 1;
                    match &key as &str {
                        "nvticache" => {
                            let values = values.first().unwrap().clone();
                            let nversion = String::from_utf8(values);
                            assert_eq!(Ok("202212101125".to_owned()), nversion);
                        }
                        "nvt:0.0.0.0.0.0.0.0.0.1" => {
                            assert_eq!(14, values.len());
                        }
                        "oid:0.0.0.0.0.0.0.0.0.1:prefs" => {
                            let values = values.first().unwrap().clone();
                            let enable_pw = String::from_utf8(values);
                            assert_eq!(
                                Ok("2|||Enable Password|||password|||".to_owned()),
                                enable_pw
                            );
                        }
                        "filename:test.nasl" => {
                            assert_eq!(values.len(), 2);
                            let mut vals = values.clone();
                            let oid = String::from_utf8(vals.pop().unwrap());
                            assert_eq!(Ok("0.0.0.0.0.0.0.0.0.1".to_owned()), oid);
                            let dummy = vals.pop().unwrap();
                            assert_eq!(Ok("1".to_owned()), String::from_utf8(dummy));
                        }
                        _ => panic!("{key} should not occur"),
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(results, 4);
    }
}
