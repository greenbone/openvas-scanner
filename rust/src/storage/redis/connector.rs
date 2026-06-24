// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::BTreeMap;
use std::fmt::Debug;

use std::path::PathBuf;
use std::str::FromStr;

use super::dberror::DbError;
use super::dberror::RedisStorageResult;
use itertools::Itertools;
use redis::*;

use crate::notus::advisories::Vulnerability;
use crate::notus::advisories::VulnerabilityData;
use crate::storage::StorageError;
use crate::storage::items::nvt;
use crate::storage::items::nvt::ACT;
use crate::storage::items::nvt::NvtKey;
use crate::storage::items::nvt::NvtPreference;
use crate::storage::items::nvt::NvtRef;
use crate::storage::items::nvt::TagKey;
use crate::storage::items::nvt::TagValue;
use greenbone_scanner_framework::models::VTData;

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

impl TryFrom<NvtKey> for KbNvtPos {
    type Error = StorageError;

    fn try_from(value: NvtKey) -> Result<Self, Self::Error> {
        Ok(match value {
            NvtKey::FileName => Self::Filename,
            NvtKey::Name => Self::Name,
            NvtKey::Dependencies => Self::Dependencies,
            NvtKey::RequiredKeys => Self::RequiredKeys,
            NvtKey::MandatoryKeys => Self::MandatoryKeys,
            NvtKey::ExcludedKeys => Self::ExcludedKeys,
            NvtKey::RequiredPorts => Self::RequiredPorts,
            NvtKey::RequiredUdpPorts => Self::RequiredUDPPorts,
            NvtKey::Category => Self::Category,
            NvtKey::Family => Self::Family,
            // tags must also be handled manually due to differentiation
            _ => {
                return Err(StorageError::UnexpectedData(format!(
                    "{value:?} is not a redis position and must be handled differently"
                )));
            }
        })
    }
}
#[derive(Default)]
pub struct RedisCtx {
    kb: Option<Connection>, //a redis connection
    pub db: u32,            // the name space
    address: String,
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
    fn from_redis_value(v: Value) -> Result<RedisValueHandler, ParsingError> {
        match &v {
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

pub const CACHE_KEY: &str = "nvticache";
pub const NOTUS_KEY: &str = "notuscache";
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
                    match redis::Commands::hset_nx(kb, DB_INDEX, dbi, 1) {
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
                    match redis::Commands::exists(kb, key) {
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
        redis::Commands::rpush(self.kb.as_mut().expect("Valid redis connection"), key, val)
            .map_err(DbError::from)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lpush<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisStorageResult<()> {
        redis::Commands::lpush(self.kb.as_mut().expect("Valid redis connection"), key, val)
            .map_err(DbError::from)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn del(&mut self, key: &str) -> RedisStorageResult<()> {
        redis::Commands::del(self.kb.as_mut().expect("Valid redis connection"), key)
            .map_err(DbError::from)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lindex(&mut self, key: &str, index: isize) -> RedisStorageResult<String> {
        let ret: RedisValueHandler = redis::Commands::lindex(
            self.kb.as_mut().expect("Valid redis connection"),
            key,
            index,
        )
        .map_err(DbError::from)?;
        Ok(ret.v)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn lrange(&mut self, key: &str, start: isize, end: isize) -> RedisStorageResult<Vec<String>> {
        let ret = redis::Commands::lrange(
            self.kb.as_mut().expect("Valid redis connection"),
            key,
            start,
            end,
        )
        .map_err(DbError::from)?;
        Ok(ret)
    }

    ///Wrapper function to avoid accessing kb member directly.
    #[inline(always)]
    fn keys(&mut self, pattern: &str) -> RedisStorageResult<Vec<String>> {
        let ret: Vec<String> =
            redis::Commands::keys(self.kb.as_mut().expect("Valid redis connection"), pattern)
                .map_err(DbError::from)?;
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
    ///
    /// To call with None is only required when using ospd-openvas and updating the feed into
    /// redis.
    fn redis_add_advisory(&mut self, adv: Option<VulnerabilityData>) -> RedisStorageResult<()> {
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
    fn redis_address(&self) -> Option<&str> {
        None
    }

    fn redis_db(&self) -> Option<u32> {
        None
    }

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
        let keyname = format!("oid:{oid}:prefs");
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

    fn redis_get_advisory(&mut self, oid: &str) -> RedisStorageResult<Option<VTData>> {
        let keyname = format!("internal/notus/advisories/{oid}");
        let nvt_data = self.lindex(&keyname, 0)?;
        if nvt_data.is_empty() {
            return Ok(None);
        }

        if let Ok(adv) = serde_json::from_str::<Vulnerability>(&nvt_data) {
            Ok(Some(nvt::Nvt::from((oid, adv)).data))
        } else {
            Ok(None)
        }
    }

    fn redis_get_nasl_vt(&mut self, oid: &str) -> RedisStorageResult<Option<VTData>> {
        let keyname = format!("nvt:{oid}");
        let nvt_data = self.lrange(&keyname, 0, -1)?;

        if nvt_data.is_empty() {
            return Ok(None);
        }

        let nvt = VTData {
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

    /// Nvt metadata is stored under two different keys
    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    fn redis_get_vt(&mut self, oid: &str) -> RedisStorageResult<Option<VTData>> {
        if let Some(vt) = self.redis_get_advisory(oid)? {
            return Ok(Some(vt));
        }

        if let Some(vt) = self.redis_get_nasl_vt(oid)? {
            return Ok(Some(vt));
        }

        let Some(address) = self.redis_address() else {
            return Ok(None);
        };
        let current_db = self.redis_db();

        if let Ok(mut rctx) = RedisCtx::open(address, NOTUSUPDATE_SELECTOR)
            && Some(rctx.db) != current_db
            && let Some(vt) = rctx.redis_get_advisory(oid)?
        {
            return Ok(Some(vt));
        }

        if let Ok(mut rctx) = RedisCtx::open(address, FEEDUPDATE_SELECTOR)
            && Some(rctx.db) != current_db
        {
            return rctx.redis_get_nasl_vt(oid);
        }

        Ok(None)
    }
}

impl RedisGetNvt for RedisCtx {
    fn redis_address(&self) -> Option<&str> {
        Some(&self.address)
    }

    fn redis_db(&self) -> Option<u32> {
        Some(self.db)
    }
}

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
                            new_xref.push(format!("{}:{}", b.class(), b.id()));
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
        prefs.sort_by_key(|b| std::cmp::Reverse(b.id.unwrap_or_default()));
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
    fn redis_add_nvt(
        &mut self,
        nvt: VTData,
        mtime: String,
        hashsum: String,
    ) -> RedisStorageResult<()> {
        let filename = nvt.filename;
        if !hashsum.is_empty() {
            let key_name = format!("sha256sums:{filename}");
            self.del(&key_name)?;
            self.rpush(&key_name, hashsum)?;
        }
        if !mtime.is_empty() {
            let key_name = format!("signaturecheck:{filename}");
            self.del(&key_name)?;
            self.rpush(&key_name, &mtime)?;
        }

        if let Some(vt_fn) = PathBuf::from(filename.clone()).extension()
            && vt_fn == "inc"
        {
            return Ok(());
        };

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
        self.rpush(
            &key_name,
            &[
                if mtime.is_empty() {
                    "1"
                } else {
                    mtime.as_str()
                },
                &oid,
            ],
        )?;

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
                        address: address.to_string(),
                    });
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeRedis {
        lists: HashMap<String, Vec<String>>,
    }

    impl FakeRedis {
        fn with_nasl(oid: &str, name: &str) -> Self {
            let mut lists = HashMap::new();
            lists.insert(
                format!("nvt:{oid}"),
                vec![
                    "test.nasl".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "summary=nasl".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    (ACT::GatherInfo as i32).to_string(),
                    "General".to_string(),
                    name.to_string(),
                ],
            );
            Self { lists }
        }

        fn add_advisory(&mut self, oid: &str, name: &str) {
            let advisory = Vulnerability {
                name: name.to_string(),
                filename: "test.notus".to_string(),
                family: "Notus".to_string(),
                category: "3".to_string(),
                ..Default::default()
            };
            self.lists.insert(
                format!("internal/notus/advisories/{oid}"),
                vec![serde_json::to_string(&advisory).expect("valid advisory json")],
            );
        }
    }

    impl RedisWrapper for FakeRedis {
        fn rpush<T: ToRedisArgs>(&mut self, _key: &str, _val: T) -> RedisStorageResult<()> {
            unimplemented!()
        }

        fn lpush<T: ToRedisArgs>(&mut self, _key: &str, _val: T) -> RedisStorageResult<()> {
            unimplemented!()
        }

        fn del(&mut self, _key: &str) -> RedisStorageResult<()> {
            unimplemented!()
        }

        fn lindex(&mut self, key: &str, index: isize) -> RedisStorageResult<String> {
            Ok(self
                .lists
                .get(key)
                .and_then(|values| values.get(index as usize))
                .cloned()
                .unwrap_or_default())
        }

        fn lrange(
            &mut self,
            key: &str,
            _start: isize,
            _end: isize,
        ) -> RedisStorageResult<Vec<String>> {
            Ok(self.lists.get(key).cloned().unwrap_or_default())
        }

        fn keys(&mut self, _pattern: &str) -> RedisStorageResult<Vec<String>> {
            unimplemented!()
        }

        fn pop(&mut self, _pattern: &str) -> RedisStorageResult<Vec<String>> {
            unimplemented!()
        }
    }

    impl RedisGetNvt for FakeRedis {}

    #[test]
    fn redis_get_vt_falls_back_to_nasl() {
        let mut redis = FakeRedis::with_nasl("1.3.6.1.4.1", "NASL VT");

        let vt = redis.redis_get_vt("1.3.6.1.4.1").unwrap().unwrap();

        assert_eq!(vt.name, "NASL VT");
        assert_eq!(vt.filename, "test.nasl");
    }

    #[test]
    fn redis_get_vt_prefers_advisory_over_nasl() {
        let mut redis = FakeRedis::with_nasl("1.3.6.1.4.2", "NASL VT");
        redis.add_advisory("1.3.6.1.4.2", "Notus Advisory");

        let vt = redis.redis_get_vt("1.3.6.1.4.2").unwrap().unwrap();

        assert_eq!(vt.name, "Notus Advisory");
        assert_eq!(vt.filename, "test.notus");
        assert_eq!(vt.family, "Notus");
    }

    #[test]
    fn redis_get_nasl_vt_excludes_advisory() {
        let mut redis = FakeRedis::default();
        redis.add_advisory("1.3.6.1.4.3", "Notus Advisory");

        assert!(redis.redis_get_nasl_vt("1.3.6.1.4.3").unwrap().is_none());

        let vt = redis.redis_get_vt("1.3.6.1.4.3").unwrap().unwrap();
        assert_eq!(vt.name, "Notus Advisory");
        assert_eq!(vt.family, "Notus");
    }
}
