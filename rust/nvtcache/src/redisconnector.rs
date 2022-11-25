use crate::dberror::DbError;
use crate::dberror::Result;
use crate::nvt::Nvt;
use redis::*;

pub enum KbNvtPos {
    NvtFilenamePos,
    NvtRequiredKeysPos,
    NvtMandatoryKeysPos,
    NvtExcludedKeysPos,
    NvtRequiredUDPPortsPos,
    NvtRequiredPortsPos,
    NvtDependenciesPos,
    NvtTagsPos,
    NvtCvesPos,
    NvtBidsPos,
    NvtXrefsPos,
    NvtCategoryPos,
    NvtFamilyPos,
    NvtNamePos,
    //The last two members aren't stored.
    NvtTimestampPos,
    NvtOIDPos,
}

/// Redis context structure which holds a stablished redis connection
/// and information necessary for handling the Nvt Cache and KBs.
pub struct RedisCtx {
    //a redis connection
    kb: Connection,
    // the name space
    db: u32,
    // max db index
    maxdb: u32,
    // the key name for the in-use list in the namespace 0
    global_db_index: String,
}

#[derive(Debug, PartialEq)]
pub struct RedisValueHandler {
    v: String,
}

impl FromRedisValue for RedisValueHandler {
    fn from_redis_value(v: &Value) -> RedisResult<RedisValueHandler> {
        match v {
            Value::Nil => Ok(RedisValueHandler { v: String::new() }),
            _ => {
                let new_var: String = from_redis_value(v).unwrap_or("".to_string());
                Ok(RedisValueHandler { v: new_var })
            }
        }
    }
}

impl RedisCtx {
    /// Connect to the redis server and return a redis context object
    pub fn new(redis_socket: &str) -> Result<RedisCtx> {
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
    fn max_db_index(&mut self) -> Result<u32> {
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
                        return 0 as u32;
                    }
                }
            }
            return 0 as u32;
        }
    }

    pub fn get_namespace(&mut self) -> Result<u32> {
        let db: u32 = self.db;
        Ok(db)
    }

    /// A custom command to change the namespace.
    /// WARNING: This change is not reflected in the kb object.
    /// Always check for the self.db for the current db index
    fn set_namespace(&mut self, db_index: u32) -> Result<()> {
        Cmd::new()
            .arg("SELECT")
            .arg(db_index.to_string())
            .query(&mut self.kb)?;

        self.db = db_index;
        Ok(())
    }

    /// Try to set a namespace index as in use in the in-use list
    fn try_database(&mut self, dbi: u32) -> Result<u32> {
        let ret = self.kb.hset_nx(&self.global_db_index, dbi, 1)?;
        Ok(ret)
    }

    /// Try to adquire ownership on a free namespace.
    /// On success, it returns the namespace index.
    fn select_database(&mut self) -> Result<u32> {
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
        return Err(DbError::NoAvailDbErr(String::from(
            "Not possible to select a free db",
        )));
    }

    /// Delete an entry from the in-use namespace's list
    fn release_namespace(&mut self) -> Result<()> {
        // Get firstthe current db index, the one to be released
        let dbi = self.get_namespace()?;
        // Remove the entry from the hash list
        self.set_namespace(0)?;
        self.kb.hdel(&self.global_db_index, dbi)?;
        Ok(())
    }

    /// Delete all keys in the namespace and relase it
    pub fn delete_namespace(&mut self) -> Result<()> {
        Cmd::new().arg("FLUSHDB").query(&mut self.kb)?;
        self.release_namespace()?;
        Ok(())
    }
    /// Set a key as redis string type
    pub fn redis_set_key<T: ToRedisArgs>(&mut self, key: &str, val: T) -> Result<()> {
        let _: () = self.kb.set(key, val)?;
        Ok(())
    }

    /// Prepend a new item to the given key, which is a redis list type
    pub fn redis_add_item<T: ToRedisArgs>(&mut self, key: &String, val: T) -> Result<String> {
        let ret: RedisValueHandler = self.kb.lpush(key, val)?;
        Ok(ret.v)
    }

    /// Get the content of the given key string type from the current namespace
    pub fn redis_get_key(&mut self, key: &str) -> Result<String> {
        let ret: RedisValueHandler = self.kb.get(key)?;
        Ok(ret.v)
    }

    /// Get and item from the key redis list type
    pub fn redis_get_item(&mut self, key: String, index: KbNvtPos) -> Result<String> {
        let ret: RedisValueHandler = self.kb.lindex(key, index as isize)?;
        Ok(ret.v)
    }

    /// Remove the given key and its content from current namespace
    pub fn redis_del_key(&mut self, key: &String) -> Result<String> {
        let ret: RedisValueHandler = self.kb.del(&key)?;
        Ok(ret.v)
    }

    /// All tag tuples in the vector are returned as a pipe separated string.
    fn tags_as_single_string(&self, tags: &Vec<(String, String)>) -> String {
        let tag: Vec<String> = tags
            .iter()
            .map(|(key, val)| format!("{}={}", key, val).to_string())
            .collect();

        tag.iter().as_ref().join("|")
    }

    /// Add an NVT in the redis cache.
    /// The NVT metadata is stored in two different keys:
    /// - 'nvt:<OID>': stores the general metadata ordered following the KbNvtPos indexes
    /// - 'oid:<OID>:prefs': stores the plugins preferences, including the script_timeout
    ///   (which is especial and uses preferences id 0)
    pub fn redis_add_nvt(&mut self, nvt: Nvt, filename: String) -> Result<()> {
        let oid = nvt.get_oid();
        let name = nvt.get_name();
        let required_keys = nvt.get_required_keys().concat();
        let mandatory_keys = nvt.get_mandatory_keys().concat();
        let excluded_keys = nvt.get_excluded_keys().concat();
        let required_udp_ports = nvt.get_required_udp_ports().concat();
        let required_ports = nvt.get_required_ports().concat();
        let dependencies = nvt.get_dependencies().concat();
        let tags = self.tags_as_single_string(nvt.get_tag());
        let category = nvt.get_category().to_string();
        let family = nvt.get_family();

        // Get the references
        let (cves, bids, xrefs) = nvt.get_refs();

        let key_name = ["nvt:".to_owned(), oid.to_owned()].join("");
        let values: Vec<&str> = [
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
            family,
            name,
        ]
        .to_vec();

        self.kb.rpush(key_name, values)?;

        // Add preferences
        let prefs = nvt.get_prefs();
        if !prefs.is_empty() {
            let key_name = ["oid:".to_owned(), oid.to_owned(), "prefs".to_owned()].join("");
            self.kb.del(&key_name)?;
            self.kb.lpush(&key_name, prefs)?;
        }

        Ok(())
    }
}
