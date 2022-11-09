use redis::*;

const GLOBAL_DBINDEX_NAME: &str = "GVM.__GlobalDBIndex";
const REDIS_DEFAULT_PATH: &str = "unix:///run/redis/redis-server.sock";

pub mod redisconnector {
    use std::result;

    use super::*;
    use crate::dberror::dberror::DbError;
    use crate::dberror::dberror::Result;

    pub struct RedisCtx {
        kb: Connection, //a redis connection
        db: u32,        // the name space
        maxdb: u32,     // max db index
    }

    impl RedisCtx {
        /// Connect to the redis server and return a redis context object
        pub fn new() -> Result<RedisCtx> {
            let client = redis::Client::open(REDIS_DEFAULT_PATH)?;
            let kb = client.get_connection()?;
            let mut redisctx = RedisCtx {
                kb,
                db: 0,
                maxdb: 0,
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
                    return Err(DbError::CustomErr(String::from(
                        "Not possible to select a free database.",
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

        fn set_namespace(&mut self, db_index: u32) -> Result<String> {
            Cmd::new()
                .arg("SELECT")
                .arg(db_index.to_string())
                .query(&mut self.kb)?;

            self.db = db_index;
            return Ok(String::from("ok"));
        }

        fn try_database(&mut self, dbi: u32) -> Result<u32> {
            let ret = self.kb.hset_nx(GLOBAL_DBINDEX_NAME, dbi, 1)?;
            Ok(ret)
        }

        fn select_database(&mut self) -> Result<u32> {
            let maxdb: u32 = self.max_db_index()?;
            let mut selected_db: u32 = 0;

            // Start always from 1. Namespace 0 is reserved
            //format GLOBAL_DBINDEX_NAME
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
            return Err(DbError::CustomErr(String::from(
                "Not possible to select a free db",
            )));
        }

        /// Delete an entry from the in-use namespace's list
        fn release_namespace(&mut self) -> Result<()> {
            // Get firstthe current db index, the one to be released
            let dbi = self.get_namespace()?;
            // Remove the entry from the hash list
            self.set_namespace(0)?;
            self.kb.hdel(GLOBAL_DBINDEX_NAME, dbi)?;
            Ok(())
        }

        /// Delete all keys in the namespace and relase the it
        pub fn delete_namespace(&mut self) -> Result<()> {
            Cmd::new().arg("FLUSHDB").query(&mut self.kb)?;
            self.release_namespace()?;
            Ok(())
        }
        //Wrapper function to avoid accessing kb member directly.
        pub fn redis_set_key<T: ToRedisArgs>(&mut self, key: &str, val: T) -> Result<()> {
            let _: () = self.kb.set(key, val)?;
            Ok(())
        }

        pub fn redis_get_key(&mut self, key: &str) -> String {
            match self.kb.get(key) {
                Ok(x) => return x,
                Err(e) => e.to_string(),
            }
        }
    }
}
