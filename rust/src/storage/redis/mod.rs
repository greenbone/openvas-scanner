// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
/// Module with structures and methods to access redis.
mod connector;
/// Module to handle custom errors
mod dberror;

use std::sync::Mutex;
use std::sync::MutexGuard;

use connector::CACHE_KEY;
/// Default selector for feed update
pub use connector::FEEDUPDATE_SELECTOR;
pub use connector::NOTUSUPDATE_SELECTOR;
pub use connector::NameSpaceSelector;
pub use connector::{RedisAddAdvisory, RedisAddNvt, RedisCtx, RedisGetNvt, RedisWrapper};
pub use dberror::{DbError, RedisStorageResult};

use super::Dispatcher;
use super::Remover;
use super::Retriever;
use super::ScanID;
use super::error::StorageError;
use super::inmemory::kb::InMemoryKbStorage;
use super::items::kb::GetKbContextKey;
use super::items::kb::KbContextKey;
use super::items::kb::KbItem;
use super::items::notus_advisory::NotusAdvisory;
use super::items::notus_advisory::NotusCache;
use super::items::nvt::Feed;
use super::items::nvt::FeedVersion;
use super::items::nvt::FileName;
use super::items::nvt::Nvt;
use super::items::nvt::Oid;

use super::items::result::ResultContextKeySingle;
use super::items::result::ResultItem;

/// Cache implementation.
///
/// This implementation is thread-safe as it stored the underlying RedisCtx within a lockable arc reference.
///
/// We need a second level cache before redis due to NVT runs.
/// In this case we need to wait until we get the OID so that we can build the key additionally
/// we need to have all references and preferences to respect the order to be downwards compatible.
/// This should be changed when there is new OSP frontend available.
#[derive(Debug, Default)]
pub struct RedisStorage<R>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    cache: Mutex<R>,
    kbs: InMemoryKbStorage,
}

impl<R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt> RedisStorage<R> {
    fn lock_cache(&self) -> Result<MutexGuard<'_, R>, DbError> {
        self.cache
            .lock()
            .map_err(|e| DbError::PoisonedLock(format!("{e:?}")))
    }
}

impl RedisStorage<RedisCtx> {
    /// Initialize and return an NVT Cache Object
    ///
    /// The redis_url must be a complete url including the used protocol e.g.:
    /// `"unix:///run/redis/redis-server.sock"`.
    pub fn init(
        redis_url: &str,
        selector: &[NameSpaceSelector],
    ) -> RedisStorageResult<RedisStorage<RedisCtx>> {
        let rctx = RedisCtx::open(redis_url, selector)?;

        Ok(RedisStorage {
            cache: Mutex::new(rctx),
            kbs: InMemoryKbStorage::default(),
        })
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

impl<S> Dispatcher<KbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = KbItem;
    fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.kbs.dispatch(key, item)
    }
}

impl<S> Retriever<KbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl<S> Retriever<GetKbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<(String, Vec<KbItem>)>;
    fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl<S> Remover<KbContextKey> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Vec<KbItem>>, StorageError> {
        self.kbs.remove(key)
    }
}

impl<S: RedisAddNvt> Dispatcher<FileName> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Nvt;
    fn dispatch(
        &self,
        _: FileName,
        item: Self::Item,
    ) -> Result<(), crate::storage::error::StorageError> {
        let mut vts = self.cache.lock()?;
        vts.redis_add_nvt(item)?;
        Ok(())
    }
}

impl<S: RedisWrapper> Dispatcher<FeedVersion> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = String;
    fn dispatch(&self, _: FeedVersion, item: Self::Item) -> Result<(), StorageError> {
        let mut vts = self.cache.lock()?;
        vts.del(CACHE_KEY)?;
        vts.rpush(CACHE_KEY, &[&item])?;
        Ok(())
    }
}

impl<S: RedisWrapper> Retriever<FeedVersion> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = String;
    fn retrieve(&self, _: &FeedVersion) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: RedisWrapper> Retriever<Feed> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<Nvt>;
    fn retrieve(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: RedisWrapper> Retriever<Oid> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Nvt;
    fn retrieve(&self, _: &Oid) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: RedisWrapper> Retriever<FileName> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Nvt;
    fn retrieve(&self, _: &FileName) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S> Dispatcher<ScanID> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ResultItem;
    fn dispatch(&self, _: ScanID, _: Self::Item) -> Result<(), StorageError> {
        unimplemented!()
    }
}

impl<S> Retriever<ResultContextKeySingle> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ResultItem;
    fn retrieve(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S> Retriever<ScanID> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<ResultItem>;
    fn retrieve(&self, _: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S> Remover<ResultContextKeySingle> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ResultItem;
    fn remove(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S> Remover<ScanID> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = Vec<ResultItem>;
    fn remove(&self, _: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: RedisAddAdvisory> Dispatcher<()> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = NotusAdvisory;
    fn dispatch(&self, _: (), item: Self::Item) -> Result<(), StorageError> {
        let mut cache = self.cache.lock()?;
        cache.redis_add_advisory(Some(item))?;
        Ok(())
    }
}

impl<S: RedisAddAdvisory> Dispatcher<NotusCache> for RedisStorage<S>
where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt,
{
    type Item = ();
    fn dispatch(&self, _: NotusCache, _: Self::Item) -> Result<(), StorageError> {
        let mut cache = self.cache.lock()?;
        cache.redis_add_advisory(None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::mpsc::{self, Sender, TryRecvError};

    use crate::storage::Dispatcher;
    use crate::storage::inmemory::kb::InMemoryKbStorage;
    use crate::storage::items::nvt::{
        ACT, FeedVersion, FileName, Nvt, NvtPreference, NvtRef, PreferenceType, TagKey, TagValue,
    };
    use crate::storage::redis::RedisStorage;

    use super::{RedisAddAdvisory, RedisAddNvt, RedisGetNvt, RedisStorageResult, RedisWrapper};

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
        let version = "202212101125".to_owned();
        let filename = "test.nasl".to_owned();
        let mut tag = BTreeMap::new();
        tag.insert(TagKey::CreationDate, TagValue::Number(23));
        let nvt = Nvt {
            oid: "0.0.0.0.0.0.0.0.0.1".to_owned(),
            name: "fancy name".to_owned(),
            filename: filename.clone(),
            tag,
            dependencies: vec!["ssh_detect.nasl".to_owned(), "ssh2.nasl".to_owned()],
            required_keys: vec!["WMI/Apache/RootPath".to_owned()],
            mandatory_keys: vec!["ssh/blubb/detected".to_owned()],
            excluded_keys: vec![
                "Settings/disable_cgi_scanning".to_owned(),
                "bla/bla".to_owned(),
            ],
            required_ports: vec!["Services/ssh".to_owned(), "22".to_owned()],
            required_udp_ports: vec!["Services/udp/unknown".to_owned(), "17".to_owned()],
            references: vec![
                NvtRef {
                    class: "cve".to_owned(),
                    id: "CVE-1999-0524".to_owned(),
                },
                NvtRef {
                    class: "http://freshmeat.sourceforge.net/projects/eventh/".to_owned(),
                    id: "URL".to_owned(),
                },
            ],
            preferences: vec![NvtPreference {
                id: Some(2),
                class: PreferenceType::Password,
                name: "Enable Password".to_owned(),
                default: "".to_owned(),
            }],
            category: ACT::Denial,
            family: "Denial of Service".to_owned(),
        };
        let (sender, rx) = mpsc::channel();
        let fr = FakeRedis { sender };
        let cache = Mutex::new(fr);
        let kbs = InMemoryKbStorage::default();
        let key = FileName(filename);
        let storage = RedisStorage { cache, kbs };
        storage.dispatch(FeedVersion, version).unwrap();
        storage.dispatch(key, nvt).unwrap();
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
