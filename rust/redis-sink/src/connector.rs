use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::Mutex;

use crate::dberror::DbError;
use crate::dberror::RedisResult;
use crate::nvt::Nvt;
use redis::*;
use sink::ACT;
use sink::GetType;
use sink::NVTField;
use sink::NVTKey;
use sink::NvtRef;
use sink::Sink;
use sink::SinkError;
use sink::StoreType;
use sink::TagKey;

pub enum KbNvtPos {
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
    //The last two members aren't stored.
    Timestamp,
    OID,
}

impl TryFrom<NVTKey> for KbNvtPos {
    type Error = DbError;

    fn try_from(value: NVTKey) -> Result<Self, Self::Error> {
        Ok(match value {
            NVTKey::Oid => Self::OID,
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
            // tags must also be handled manually due to differenciation
            _ => {
                return Err(DbError::CustomErr(format!(
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

#[derive(Debug, PartialEq)]
pub struct RedisValueHandler {
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
    pub fn new(redis_socket: &str) -> RedisResult<RedisCtx> {
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
    fn max_db_index(&mut self) -> RedisResult<u32> {
        if self.maxdb > 0 {
            return Ok(self.maxdb);
        }

        let maxdb = Cmd::new()
            .arg("CONFIG")
            .arg("GET")
            .arg("databases")
            .query(&mut self.kb);

        match maxdb {
            Ok(mdb) => {
                let res: Vec<String> = mdb;
                self.maxdb = max_db_index_to_uint(res);
                return Ok(self.maxdb);
            }
            Err(_) => {
                return Err(DbError::MaxDbErr(String::from(
                    "Not possible to get the Max. database index.",
                )))
            }
        }
        /// Redis always replies about config with a vector
        /// of 2 string ["databases", "Number"]
        /// Therefore we convert the "Number" to uint32
        fn max_db_index_to_uint(res: Vec<String>) -> u32 {
            if res.len() == 2 {
                match res[1].to_string().parse::<u32>() {
                    Ok(m) => return m,
                    Err(e) => {
                        println!("{}", e);
                        return 0_u32;
                    }
                }
            }
            0_u32
        }
    }

    pub fn namespace(&mut self) -> RedisResult<u32> {
        let db: u32 = self.db;
        Ok(db)
    }

    fn set_namespace(&mut self, db_index: u32) -> RedisResult<()> {
        Cmd::new()
            .arg("SELECT")
            .arg(db_index.to_string())
            .query(&mut self.kb)?;

        self.db = db_index;
        Ok(())
    }

    fn try_database(&mut self, dbi: u32) -> RedisResult<u32> {
        let ret = self.kb.hset_nx(&self.global_db_index, dbi, 1)?;
        Ok(ret)
    }

    fn select_database(&mut self) -> RedisResult<u32> {
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
    fn release_namespace(&mut self) -> RedisResult<()> {
        // Get firstthe current db index, the one to be released
        let dbi = self.namespace()?;
        // Remove the entry from the hash list
        self.set_namespace(0)?;
        self.kb.hdel(&self.global_db_index, dbi)?;
        Ok(())
    }

    /// Delete all keys in the namespace and relase the it
    pub fn delete_namespace(&mut self) -> RedisResult<()> {
        Cmd::new().arg("FLUSHDB").query(&mut self.kb)?;
        self.release_namespace()?;
        Ok(())
    }
    //Wrapper function to avoid accessing kb member directly.
    pub fn redis_set_key<T: ToRedisArgs>(&mut self, key: &str, val: T) -> RedisResult<()> {
        self.kb.set(key, val)?;
        Ok(())
    }

    pub fn lpush<T: ToRedisArgs>(&mut self, key: String, val: T) -> RedisResult<String> {
        let ret: RedisValueHandler = self.kb.lpush(key, val)?;
        Ok(ret.v)
    }

    pub fn rpush<T: ToRedisArgs>(&mut self, key: String, val: T) -> RedisResult<String> {
        let ret: RedisValueHandler = self.kb.rpush(key, val)?;
        Ok(ret.v)
    }
    pub fn redis_key(&mut self, key: &str) -> RedisResult<String> {
        let ret: RedisValueHandler = self.kb.get(key)?;
        Ok(ret.v)
    }

    pub fn lindex(&mut self, key: &str, index: KbNvtPos) -> RedisResult<String> {
        let ret: RedisValueHandler = self.kb.lindex(key, index as isize)?;
        Ok(ret.v)
    }

    pub fn redis_del_key(&mut self, key: String) -> RedisResult<String> {
        let ret: RedisValueHandler = self.kb.del(key)?;
        Ok(ret.v)
    }

    fn tags_as_single_string(&self, tags: &[(String, String)]) -> String {
        let tag: Vec<String> = tags
            .iter()
            .map(|(key, val)| format!("{}={}", key, val))
            .collect();

        tag.iter().as_ref().join("|")
    }
    /// Add an NVT in the redis cache.
    /// The NVT metadata is stored in two different keys:
    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    pub fn redis_add_nvt(&mut self, nvt: &Nvt) -> RedisResult<()> {
        // TODO remove here
        let oid = nvt.oid();
        let name = nvt.name();
        // TODO verify, before it was concat without delimeter which seems wrong
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

        let key_name = ["nvt:".to_owned(), oid.to_owned()].join("");
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
            let key_name = ["oid:".to_owned(), oid.to_owned(), "prefs".to_owned()].join("");
            self.kb.lpush(key_name, prefs)?;
        }

        Ok(())
    }
}

/// Cache implementation.
///
/// This implementation is threadsafe as it stored the underlying RedisCtx within a lockable arc reference.
/// We need a second level cache before redis due to NVT runs. In this case we need to have the complete data to get the ordering right.
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

