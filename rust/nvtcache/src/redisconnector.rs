use crate::dberror::DbError;
use crate::dberror::RedisResult;
use crate::nvt::Nvt;
use redis::*;
use sink::GetType;
use sink::NVTKey;

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

    pub fn redis_add_nvt(&mut self, nvt: Nvt) -> RedisResult<()> {
        // TODO remove here
        let oid = nvt.oid();
        let name = nvt.name();
        let required_keys = nvt.required_keys().concat();
        let mandatory_keys = nvt.mandatory_keys().concat();
        let excluded_keys = nvt.excluded_keys().concat();
        let required_udp_ports = nvt.required_udp_ports().concat();
        let required_ports = nvt.required_ports().concat();
        let dependencies = nvt.dependencies().concat();
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
