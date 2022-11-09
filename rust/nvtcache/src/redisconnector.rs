use redis::*;

const GLOBAL_DBINDEX_NAME: &str = "GVM.__GlobalDBIndex";
const REDIS_DEFAULT_PATH: &str = "unix:///run/redis/redis-server.sock";
const NVTCACHE: &str = "nvticache";

pub mod redisconnector {
    use std::result;

    use super::*;
    use crate::dberror::dberror::DbError;
    use crate::dberror::dberror::Result;

    pub struct RedisCtx {
        pub kb: Connection, //a redis connection
        db: u32,            // the name space
        maxdb: u32,         // max db index
    }

    impl RedisCtx {
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

        pub fn max_db_index(&mut self) -> Result<u32> {
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
        pub fn set_namespace(&mut self, db_index: u32) -> Result<String> {
            if db_index <= 0 {
                return Err(DbError::CustomErr(String::from(
                    "Invalid selected db index {db_index}. It must be greater than ",
                )));
            }
            Cmd::new()
                .arg("SELECT")
                .arg(db_index.to_string())
                .query(&mut self.kb)?;

            self.db = db_index;
            return Ok(String::from("ok"));
        }

        pub fn try_database(&mut self, dbi: u32) -> Result<u32> {
            let ret = self.kb.hset_nx(GLOBAL_DBINDEX_NAME, dbi, 1)?;
            Ok(ret)
        }

        pub fn select_database(&mut self) -> Result<u32> {
            let maxdb: u32 = self.max_db_index()?;
            let mut selected_db: u32 = 0;
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

        pub fn redis_set_key_int(&mut self, key: &str, val: i32) -> Result<()> {
            let _: () = self.kb.set(key, val)?;
            Ok(())
        }

        pub fn redis_get_int(&mut self, key: &str) -> String {
            match self.kb.get(key) {
                Ok(x) => return x,
                Err(e) => e.to_string(),
            }
        }
    }
}
