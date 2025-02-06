// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::BTreeMap;
use std::fmt::Debug;

use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use super::dberror::DbError;
use super::dberror::RedisStorageResult;
use itertools::Itertools;
use redis::*;

use crate::models;
use crate::models::Vulnerability;
use crate::storage;
use crate::storage::item::ItemDispatcher;
use crate::storage::item::NVTKey;
use crate::storage::item::Nvt;
use crate::storage::item::NvtPreference;
use crate::storage::item::NvtRef;
use crate::storage::item::PerItemDispatcher;
use crate::storage::item::TagKey;
use crate::storage::item::TagValue;
use crate::storage::item::ACT;
use crate::storage::ContextKey;
use crate::storage::Field;
use crate::storage::Kb;
use crate::storage::NotusAdvisory;
use crate::storage::Retrieve;
use crate::storage::Retriever;
use crate::storage::StorageError;

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

impl TryFrom<NVTKey> for KbNvtPos {
    type Error = StorageError;

    fn try_from(value: NVTKey) -> Result<Self, Self::Error> {
        Ok(match value {
            NVTKey::FileName => Self::Filename,
            NVTKey::Name => Self::Name,
            NVTKey::Dependencies => Self::Dependencies,
            NVTKey::RequiredKeys => Self::RequiredKeys,
            NVTKey::MandatoryKeys => Self::MandatoryKeys,
            NVTKey::ExcludedKeys => Self::ExcludedKeys,
            NVTKey::RequiredPorts => Self::RequiredPorts,
            NVTKey::RequiredUdpPorts => Self::RequiredUDPPorts,
            NVTKey::Category => Self::Category,
            NVTKey::Family => Self::Family,
            // tags must also be handled manually due to differentiation
            _ => {
                return Err(StorageError::UnexpectedData(format!(
                    "{value:?} is not a redis position and must be handled differently"
                )))
            }
        })
    }
}
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
    fn del(&mut self, key: &str) -> RedisStorageResult<()>;
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
    fn del(&mut self, key: &str) -> RedisStorageResult<()> {
        self.kb
            .as_mut()
            .expect("Valid redis connection")
            .del(key)
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
    ///
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
                let value = Vulnerability::from(data);
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
                match tk {
                    TagKey::CreationDate | TagKey::LastModification | TagKey::SeverityDate => {
                        tag_map.insert(
                            tk,
                            TagValue::from(i64::from_str(v).expect("Valid timestamp")),
                        )
                    }
                    _ => tag_map.insert(tk, TagValue::from(v)),
                };
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

        if let Ok(adv) = serde_json::from_str::<Vulnerability>(&nvt_data) {
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
                match ACT::from_str(&nvt_data[KbNvtPos::Category as usize]) {
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

        (
            cves.iter().as_ref().join(", "),
            bids.iter().as_ref().join(", "),
            xrefs.iter().as_ref().join(", "),
        )
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
    ///
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
        self.del(&key_name)?;
        self.rpush(&key_name, &values)?;

        // Add preferences
        let prefs = Self::prefs(&nvt.preferences);
        if !prefs.is_empty() {
            let key_name = format!("oid:{oid}:prefs");
            self.del(&key_name)?;
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
            .query::<()>(&mut self.kb.as_mut().expect("Valid redis connection"))?;
        Ok(())
    }

    /// Delete all keys in the namespace and release the it
    pub fn delete_namespace(&mut self) -> RedisStorageResult<()> {
        Cmd::new()
            .arg("FLUSHDB")
            .query::<()>(&mut self.kb.as_mut().expect("Valid redis connection"))?;
        self.release_namespace()?;
        Ok(())
    }

    /// Clean up the namespace.
    pub fn flush_namespace(&mut self) -> RedisStorageResult<()> {
        Cmd::new()
            .arg("FLUSHDB")
            .query::<()>(&mut self.kb.as_mut().expect("Valid redis connection"))?;
        Ok(())
    }

    //Wrapper function to avoid accessing kb member directly.
    pub fn set_value<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
        () = self
            .kb
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
    cache: Arc<Mutex<R>>,
    kbs: Arc<Mutex<Vec<Kb>>>,
}

impl<R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt> CacheDispatcher<R> {
    fn lock_cache(&self) -> Result<MutexGuard<'_, R>, DbError> {
        self.cache
            .lock()
            .map_err(|e| DbError::PoisonedLock(format!("{e:?}")))
    }
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
            cache: Arc::new(Mutex::new(rctx)),
            kbs: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Creates a dispatcher to be used to update the feed for a ospd service
    ///
    /// Initializes a redis cache based on the given selector and url and clears the namespace
    /// before returning the underlying cache as a Dispatcher.
    pub fn as_dispatcher(
        redis_url: &str,
        selector: &[NameSpaceSelector],
    ) -> RedisStorageResult<PerItemDispatcher<CacheDispatcher<RedisCtx>>> {
        let cache = Self::init(redis_url, selector)?;
        cache.flushdb()?;
        Ok(PerItemDispatcher::new(cache))
    }

    /// Reset the NVT Cache and release the redis namespace
    pub fn reset(&self) -> RedisStorageResult<()> {
        self.lock_cache()?.delete_namespace()
    }

    /// Reset the NVT Cache. Do not release the namespace. Only ensure it is clean
    pub fn flushdb(&self) -> RedisStorageResult<()> {
        self.lock_cache()?.flush_namespace()
    }
}

impl<S> ItemDispatcher for CacheDispatcher<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    fn dispatch_nvt(&self, nvt: Nvt) -> Result<(), StorageError> {
        let mut cache = Arc::as_ref(&self.cache).lock()?;
        cache.redis_add_nvt(nvt).map_err(|e| e.into())
    }

    fn dispatch_feed_version(&self, version: String) -> Result<(), StorageError> {
        let mut cache = Arc::as_ref(&self.cache).lock()?;
        cache.del(CACHE_KEY)?;
        cache.rpush(CACHE_KEY, &[&version]).map_err(|e| e.into())
    }

    fn dispatch_kb(&self, _: &ContextKey, kb: Kb) -> Result<(), StorageError> {
        let mut kbs = self.kbs.lock().map_err(StorageError::from)?;
        kbs.push(kb);
        Ok(())
    }
    fn dispatch_advisory(&self, key: &str, adv: Option<NotusAdvisory>) -> Result<(), StorageError> {
        let mut cache = Arc::as_ref(&self.cache).lock()?;
        cache.redis_add_advisory(key, adv).map_err(|e| e.into())
    }
}

impl<S> Retriever for CacheDispatcher<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Send,
{
    fn retrieve(
        &self,
        _: &ContextKey,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError> {
        Ok(match scope {
            Retrieve::NotusAdvisory(_) | Retrieve::NVT(_) | Retrieve::Result(_) => {
                Box::new(Vec::new().into_iter())
            }
            Retrieve::KB(s) => Box::new({
                let kbs = self.kbs.lock().map_err(StorageError::from)?;
                let kbs = kbs.clone();
                kbs.into_iter()
                    .filter(move |x| x.key == s)
                    .map(move |x| Field::KB(x.clone()))
            }),
        })
    }

    fn retrieve_by_field(
        &self,
        _field: Field,
        _scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = (ContextKey, Field)>>, StorageError> {
        unimplemented!()
    }

    fn retrieve_by_fields(&self, _: Vec<Field>, _: Retrieve) -> storage::FieldKeyResult {
        todo!()
    }
}

impl<S> storage::Remover for CacheDispatcher<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Send,
{
    fn remove_kb(
        &self,
        _key: &ContextKey,
        _kb_key: Option<String>,
    ) -> Result<Option<Vec<Kb>>, StorageError> {
        unimplemented!()
    }

    fn remove_result(
        &self,
        _key: &ContextKey,
        _result_id: Option<usize>,
    ) -> Result<Option<Vec<models::Result>>, StorageError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, Sender, TryRecvError};
    use std::sync::{Arc, Mutex};

    use super::super::dberror::RedisStorageResult;
    use super::{CacheDispatcher, RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisWrapper};
    use crate::storage::item::NVTField::*;
    use crate::storage::item::PerItemDispatcher;
    use crate::storage::item::{NvtPreference, NvtRef, PreferenceType, TagKey, TagValue, ACT};
    use crate::storage::Field::NVT;
    use crate::storage::{ContextKey, Dispatcher};

    #[derive(Clone)]
    struct FakeRedis {
        sender: Sender<(String, Vec<Vec<u8>>)>,
    }
    impl RedisWrapper for FakeRedis {
        fn rpush<T: redis::ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
            self.sender
                .send((key.to_owned(), val.to_redis_args()))
                .unwrap();
            Ok(())
        }

        fn lpush<T: redis::ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
            self.sender
                .send((key.to_owned(), val.to_redis_args()))
                .unwrap();
            Ok(())
        }
        fn del(&mut self, _: &str) -> RedisStorageResult<()> {
            Ok(())
        }

        fn lindex(&mut self, _: &str, _: isize) -> RedisStorageResult<String> {
            Ok(String::new())
        }

        fn keys(&mut self, _: &str) -> RedisStorageResult<Vec<String>> {
            Ok(Vec::new())
        }
        fn pop(&mut self, _: &str) -> RedisStorageResult<Vec<String>> {
            Ok(Vec::new())
        }

        fn lrange(&mut self, _: &str, _: isize, _: isize) -> RedisStorageResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    impl RedisAddNvt for FakeRedis {}
    impl RedisAddAdvisory for FakeRedis {}
    impl RedisGetNvt for FakeRedis {}

    #[test]
    fn transform_nvt() {
        let commands = [
            NVT(Version("202212101125".to_owned())),
            NVT(Tag(TagKey::CreationDate, TagValue::Number(23))),
            NVT(Name("fancy name".to_owned())),
            NVT(Category(ACT::Denial)),
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
                },
                NvtRef {
                    class: "http://freshmeat.sourceforge.net/projects/eventh/".to_owned(),
                    id: "URL".to_owned(),
                },
            ])),
            NVT(RequiredKeys(vec!["WMI/Apache/RootPath".to_owned()])),
            NVT(Oid("0.0.0.0.0.0.0.0.0.1".to_owned())),
            NVT(FileName("test.nasl".to_owned())),
            NVT(Preference(NvtPreference {
                id: Some(2),
                class: PreferenceType::Password,
                name: "Enable Password".to_owned(),
                default: "".to_owned(),
            })),
        ];
        let (sender, rx) = mpsc::channel();
        let fr = FakeRedis { sender };
        let cache = Arc::new(Mutex::new(fr));
        let kbs = Arc::new(Mutex::new(Vec::new()));
        let rcache = CacheDispatcher { cache, kbs };
        let dispatcher = PerItemDispatcher::new(rcache);
        let key = ContextKey::FileName("test.nasl".to_string());
        for c in commands {
            dispatcher.dispatch(&key, c).unwrap();
        }
        dispatcher.on_exit(&key).unwrap();
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
