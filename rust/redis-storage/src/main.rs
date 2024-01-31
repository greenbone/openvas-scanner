
use redis_storage::{CacheDispatcher, VtHelper, FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR};
use storage::Storage;

use storage::item::ItemDispatcher;
use storage::{Retriever, ListRetriever, Retrieve};

fn main() {

    let redis= "unix:///run/redis-openvas/redis.sock";


    
    let notus_cache: CacheDispatcher<redis_storage::RedisCtx, &dyn AsRef<str>> = CacheDispatcher::init(redis, NOTUSUPDATE_SELECTOR).unwrap();
    
    let vts_cache: CacheDispatcher<redis_storage::RedisCtx, &dyn AsRef<str>> = CacheDispatcher::init(redis, FEEDUPDATE_SELECTOR).unwrap();
    let cache = VtHelper::new(notus_cache, vts_cache);
    
    println!("{:?}",cache.get_oids().unwrap().len());
    for oid in cache.get_oids().unwrap() {
        let metadata = cache.retrieve_single_nvt(&oid).unwrap();
        let json_str = serde_json::to_string(&metadata).unwrap();
        println!("{json_str}");
    }

}

