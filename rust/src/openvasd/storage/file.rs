// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    io,
    marker::{Send, Sync},
    ops::Deref,
    path::Path,
    sync::RwLock,
};

use crate::crypt::ChaCha20Crypt;
use models::{Scan, Status};
use scannerlib::{
    models,
    storage::{
        error::StorageError,
        infisto::{
            ChaCha20IndexFileStorer, IndexedByteStorage, IndexedByteStorageIterator,
            IndexedFileStorer, Range, Serialization,
        },
        inmemory::InMemoryStorage,
    },
};
use tokio::task::spawn_blocking;

use super::{inmemory, *};

pub struct Storage<S> {
    storage: Arc<RwLock<S>>,
    // we use inmemory for NVT and KB items as we need to continuously when starting or running a
    // scan. KB items should be deleted when a target/scan is finished.
    underlying: inmemory::Storage<crypt::ChaCha20Crypt>,
}

pub fn unencrypted<P>(path: P, feeds: Vec<FeedHash>) -> Result<Storage<IndexedFileStorer>, Error>
where
    P: AsRef<Path>,
{
    let ifs = IndexedFileStorer::init(path)?;
    Ok(Storage::new(ifs, feeds))
}

pub fn encrypted<P, K>(
    path: P,
    key: K,
    feeds: Vec<FeedHash>,
) -> Result<Storage<ChaCha20IndexFileStorer<IndexedFileStorer>>, Error>
where
    P: AsRef<Path>,
    K: Into<scannerlib::storage::infisto::Key>,
{
    let ifs = IndexedFileStorer::init(path)?;
    let ifs = ChaCha20IndexFileStorer::new(ifs, key);
    Ok(Storage::new(ifs, feeds))
}

impl<S> Storage<S> {
    pub fn new(s: S, feeds: Vec<FeedHash>) -> Self {
        Storage {
            storage: Arc::new(s.into()),
            underlying: inmemory::Storage::new(ChaCha20Crypt::default(), feeds),
        }
    }
}

impl<S> Storage<S>
where
    S: IndexedByteStorage + Sync + Send + Clone + 'static,
{
    fn get_results_sync(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        use scannerlib::storage::infisto::Range;
        let range = {
            match (from, to) {
                (None, None) => Range::All,
                (None, Some(to)) => Range::Until(to),
                (Some(from), None) => Range::From(from),
                (Some(from), Some(to)) => Range::Between(from, to),
            }
        };
        let key = format!("results_{id}");
        let storage = &self.storage.read().unwrap();
        let storage: S = storage.deref().clone();
        let iter = IndexedByteStorageIterator::<_, Vec<u8>>::by_range(&key, storage, range)?;
        let parsed = iter.filter_map(|x| x.ok());
        Ok(Box::new(parsed))
    }
}

#[async_trait]
impl<S> ProgressGetter for Storage<S>
where
    S: IndexedByteStorage + Sync + Send + Clone + 'static,
{
    async fn get_decrypted_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        // the encryption is done in whole, unlike when in memory
        self.get_scan(id).await
    }

    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        self.get_results_sync(id, from, to)
    }

    async fn get_scan(&self, id: &str) -> Result<(Scan, Status), Error> {
        let key = format!("scan_{id}");
        let status_key = format!("status_{id}");

        let storage = Arc::clone(&self.storage);

        spawn_blocking(move || {
            let storage = storage.read().unwrap();
            let scans: Vec<Serialization<Scan>> = storage.by_range(&key, Range::All)?;
            let status: Vec<Serialization<Status>> = storage.by_range(&status_key, Range::All)?;

            match scans.first() {
                Some(Serialization::Deserialized(scan)) => match status.first() {
                    Some(Serialization::Deserialized(status)) => Ok((scan.clone(), status.clone())),
                    Some(_) => Err(Error::Serialization),
                    None => Err(Error::NotFound),
                },
                Some(_) => Err(Error::Serialization),
                None => Err(Error::NotFound),
            }
        })
        .await
        .unwrap()
    }

    async fn get_scan_ids(&self) -> Result<Vec<String>, Error> {
        let storage = Arc::clone(&self.storage);
        spawn_blocking(move || {
            let storage = &storage.read().unwrap();
            let scans: Vec<Serialization<String>> = match storage.by_range("scans", Range::All) {
                Ok(s) => s,
                Err(scannerlib::storage::infisto::Error::IoError(
                    scannerlib::storage::infisto::IoErrorKind::FileOpen,
                    io::ErrorKind::NotFound,
                )) => {
                    vec![]
                }
                Err(e) => return Err(e.into()),
            };
            let mut scans: Vec<_> = scans
                .into_iter()
                .filter_map(|x| match x {
                    Serialization::Serialized(_) => None,
                    Serialization::Deserialized(x) => Some(x),
                })
                .collect();
            scans.sort();
            scans.dedup();
            Ok(scans)
        })
        .await
        .unwrap()
    }

    async fn get_status(&self, id: &str) -> Result<Status, Error> {
        let key = format!("status_{id}");
        let storage = Arc::clone(&self.storage);

        spawn_blocking(move || {
            let storage = &storage.read().unwrap();
            let status: Vec<Serialization<Status>> = storage.by_range(&key, Range::All)?;
            match status.first() {
                Some(Serialization::Deserialized(status)) => Ok(status.clone()),
                Some(_) => Err(Error::Serialization),
                None => Err(Error::NotFound),
            }
        })
        .await
        .unwrap()
    }
}

#[async_trait]
impl<S> AppendFetchResult for Storage<S>
where
    S: IndexedByteStorage + Sync + Send + Clone + 'static,
{
    async fn append_fetched_result(
        &self,
        kind: ScanResultKind,
        r: ScanResults,
    ) -> Result<(), Error> {
        let id = &r.id;

        let status = match kind {
            ScanResultKind::StatusOverride => r.status,
            ScanResultKind::StatusAddition => {
                let scan_status = self.get_status(&r.id).await?;
                let mut status = r.status;
                // TODO: change signature
                status.update_with(&scan_status);
                status
            }
        };

        self.update_status(id, status).await?;
        if r.results.is_empty() {
            return Ok(());
        }

        let key = format!("results_{id}");
        let storage = Arc::clone(&self.storage);
        tracing::trace!(key, results_len = r.results.len());

        spawn_blocking(move || {
            let storage = &mut storage.write().unwrap();
            let results = r.results;
            let mut serialized_results = Vec::with_capacity(results.len());
            let ilen = match storage.indices(&key) {
                Ok(x) => x.len(),
                Err(_) => 0,
            };
            for (i, mut result) in results.into_iter().enumerate() {
                result.id = ilen + i;
                let bytes = serde_json::to_vec(&result)?;
                serialized_results.push(bytes);
            }
            storage.append_all(&key, &serialized_results)?;
            Ok::<_, Error>(())
        })
        .await
        .unwrap()?;
        Ok(())
    }
}

#[async_trait]
impl<S> ScanStorer for Storage<S>
where
    S: IndexedByteStorage + Sync + Send + Clone + 'static,
{
    async fn insert_scan(&self, scan: Scan) -> Result<(), Error> {
        let id = scan.scan_id.clone();
        let key = format!("scan_{id}");
        let status_key = format!("status_{id}");
        let storage = self.storage.clone();
        spawn_blocking(move || {
            let scan = Serialization::serialize(scan)?;
            let status = Serialization::serialize(Status::default())?;
            let mut storage = storage.write().unwrap();
            storage.put(&key, scan)?;
            storage.put(&status_key, status)?;

            let stored_key = Serialization::serialize(&id)?;
            storage.append("scans", stored_key)?;
            Ok(())
        })
        .await
        .unwrap()
    }

    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        let key = format!("scan_{id}");
        let status_key = format!("status_{id}");
        let results_key = format!("results_{id}");
        let storage = Arc::clone(&self.storage);
        let ids = self.get_scan_ids().await?;
        let ids: Vec<_> = ids
            .into_iter()
            .filter(|x| x != id)
            .filter_map(|x| Serialization::serialize(x).ok())
            .collect();

        spawn_blocking(move || {
            // we ignore results errors as there may or may not be results
            let mut storage = storage.write().unwrap();
            tracing::debug!(results_key, "removing results");
            let _ = storage.remove(&results_key);
            tracing::debug!(key, "removing scan");
            storage.remove(&key)?;
            tracing::debug!(status_key, "removing status");
            storage.remove(&status_key)?;
            storage.remove("scans")?;
            storage.append_all("scans", &ids)?;
            Ok(())
        })
        .await
        .unwrap()
    }

    async fn update_status(&self, id: &str, status: Status) -> Result<(), Error> {
        let key = format!("status_{id}");
        let storage = Arc::clone(&self.storage);

        spawn_blocking(move || {
            let status = Serialization::serialize(status)?;
            let mut storage = storage.write().unwrap();
            storage.put(&key, status)?;
            Ok(())
        })
        .await
        .unwrap()
    }
}

#[async_trait]
impl<S> ScanIDClientMapper for Storage<S>
where
    S: IndexedByteStorage + Sync + Send + Clone + 'static,
{
    async fn list_mapped_scan_ids(
        &self,
        client: &ClientHash,
    ) -> Result<Vec<String>, crate::storage::Error> {
        let key = "idmap";
        let storage = Arc::clone(&self.storage);
        let client_id = client.clone();

        spawn_blocking(move || {
            use scannerlib::storage::infisto::Serialization;
            let storage = storage.read().unwrap();

            let ids: Vec<Serialization<(ClientHash, String)>> = storage
                .by_range(key, scannerlib::storage::infisto::Range::All)
                .unwrap_or_default();
            let new: Vec<String> = ids
                .into_iter()
                .map(|x| x.deserialize())
                .filter_map(|x| x.ok())
                .filter(|(x, _)| x == &client_id)
                .map(|(_, x)| x)
                .collect();
            Ok(new)
        })
        .await
        .unwrap()
    }
    async fn get_mapped_id(
        &self,
        client: &ClientHash,
        scan_id: &str,
    ) -> Result<MappedID, crate::storage::Error> {
        match self
            .list_mapped_scan_ids(client)
            .await?
            .into_iter()
            .find(|x| x == scan_id)
        {
            Some(x) => Ok(x),
            None => Err(crate::storage::Error::NotFound),
        }
    }
    async fn generate_mapped_id(
        &self,
        client_id: ClientHash,
        scan_id: String,
    ) -> Result<MappedID, Error> {
        let key = "idmap";
        let storage = Arc::clone(&self.storage);

        spawn_blocking(move || {
            let idt = Serialization::serialize((client_id, scan_id.clone()))?;
            let mut storage = storage.write().unwrap();
            storage.append(key, idt)?;
            Ok(scan_id)
        })
        .await
        .unwrap()
    }

    async fn remove_mapped_id(&self, scan_id: &str) -> Result<(), Error> {
        let key = "idmap";
        let storage = Arc::clone(&self.storage);
        let sid = scan_id.to_owned();

        spawn_blocking(move || {
            use scannerlib::storage::infisto::Serialization;
            let mut storage = storage.write().unwrap();

            let ids: Vec<Serialization<(ClientHash, String)>> =
                storage.by_range(key, scannerlib::storage::infisto::Range::All)?;
            let new: Vec<Serialization<(ClientHash, String)>> = ids
                .into_iter()
                .map(|x| x.deserialize())
                .filter_map(|x| x.ok())
                .filter(|(_, x)| x != &sid)
                .map(Serialization::serialize)
                .filter_map(|x| x.ok())
                .collect();

            storage.remove(key)?;
            storage.append_all(key, &new)?;
            Ok(())
        })
        .await
        .unwrap()
    }
}

#[async_trait]
impl<S> NVTStorer for Storage<S>
where
    S: IndexedByteStorage + Sync + Send + Clone + 'static,
{
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        self.underlying.synchronize_feeds(hash).await
    }

    async fn oids(&self) -> Result<Vec<String>, Error> {
        self.underlying.oids().await
    }

    async fn vts<'a>(&self) -> Result<Vec<Nvt>, Error> {
        self.underlying.vts().await
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.underlying.feed_hash().await
    }

    async fn current_feed_version(&self) -> Result<String, Error> {
        self.underlying.current_feed_version().await
    }

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error> {
        self.underlying.vt_by_oid(oid).await
    }
}

impl FromConfigAndFeeds for Storage<ChaCha20IndexFileStorer<IndexedFileStorer>> {
    async fn from_config_and_feeds(
        config: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        // If this is even being called, we can assume we have a key
        let key = config.storage.fs.key.as_ref().unwrap();
        Ok(file::encrypted(&config.storage.fs.path, key, feeds)?)
    }
}

impl FromConfigAndFeeds for Storage<IndexedFileStorer> {
    async fn from_config_and_feeds(
        config: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(file::unencrypted(&config.storage.fs.path, feeds)?)
    }
}

impl<S> super::ResultHandler for Storage<S>
where
    S: IndexedByteStorage + Sync + Send + Clone + 'static,
{
    fn underlying_storage(&self) -> &Arc<InMemoryStorage> {
        self.underlying.underlying_storage()
    }

    fn handle_result<E>(&self, key: &str, result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>,
    {
        tracing::trace!(?key, ?result);
        let store = &mut self.storage.write().unwrap();
        let key = format!("results_{key}");

        let ilen = match store.indices(&key) {
            Ok(x) => x.len(),
            Err(_) => 0,
        };
        let results = vec![result];
        let mut serialized_results = Vec::with_capacity(results.len());
        for (i, mut result) in results.into_iter().enumerate() {
            result.id = ilen + i;
            let bytes = serde_json::to_vec(&result).map_err(|x| {
                StorageError::UnexpectedData(format!("Unable to serialize results: {x}"))
            })?;
            serialized_results.push(bytes);
        }
        store
            .append_all(&key, &serialized_results)
            .map_err(|x| StorageError::Dirty(format!("Unable to store to disk: {x}")))?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;

    use models::{Phase, Scan, Status};
    use scannerlib::storage::infisto::{CachedIndexFileStorer, IndexedByteStorage};
    use tracing::debug;

    use crate::{
        crypt::ChaCha20Crypt,
        storage::{file, inmemory},
    };

    use super::*;

    pub async fn nasl_root() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("examples")
            .join("feed")
            .join("nasl")
    }

    pub async fn example_feeds() -> Vec<FeedHash> {
        let nfp = nasl_root().await;
        let nofp = nfp.parent().unwrap().join("notus").join("advisories");
        debug!(nasl_feed=?nfp, notus_advisories_feed=?nofp);
        vec![FeedHash::nasl(nfp), FeedHash::advisories(nofp)]
    }

    /// Creates a Storage with a cached file storer based on the feed found `rust/examples/feed/`.
    pub async fn example_feed_file_storage(target: &str) -> Storage<CachedIndexFileStorer> {
        let storage = CachedIndexFileStorer::init(target).unwrap();
        let result = file::Storage::new(storage, example_feeds().await);
        result
            .synchronize_feeds(example_feeds().await)
            .await
            .unwrap();
        result
    }

    fn clear_tmp_files(tmp_path: &Path) {
        let remove = |filename| {
            let _ = fs::remove_file(tmp_path.join(filename));
        };
        remove("scan_aha.dat");
        remove("scan_aha.idx");
        remove("status_aha.dat");
        remove("status_aha.idx");
        remove("scans.dat");
        remove("scans.idx");
    }

    #[tokio::test]
    async fn credentials() {
        let jraw = r#"
    {
      "target": {
        "hosts": [
          "192.168.123.52"
        ],
        "ports": [
          {
            "protocol": "tcp",
            "range": [
              {
                "start": 22,
                "end": 22
              }
            ]
          }
        ],
        "credentials": [
          {
            "service": "ssh",
            "port": 22,
            "up": {
              "username": "msfadmin",
              "password": "msfadmin"
            }
          }
        ]
      },
      "vts": [
        {
          "oid": "1.3.6.1.4.1.25623.1.0.90022"
        }
      ]
    }
            "#;
        let mut scan: Scan = serde_json::from_str(jraw).unwrap();
        scan.scan_id = "aha".to_string();
        let tmp_path = "/tmp/openvasd/credential";
        clear_tmp_files(Path::new(tmp_path));
        let storage = example_feed_file_storage(tmp_path).await;
        storage.insert_scan(scan.clone()).await.unwrap();
        let (scan2, _) = storage.get_scan("aha").await.unwrap();
        assert_eq!(scan, scan2);
    }

    #[tokio::test]
    async fn oids() {
        let file_storage = example_feed_file_storage("/tmp/openvasd/oids").await;
        let feeds = file_storage.feed_hash().await;
        file_storage.synchronize_feeds(feeds.clone()).await.unwrap();
        let amount_file_oids = file_storage.oids().await.unwrap().len();

        let memory_storage = inmemory::Storage::new(ChaCha20Crypt::default(), feeds.clone());
        memory_storage.synchronize_feeds(feeds).await.unwrap();
        let amount_memory_oids = memory_storage.oids().await.unwrap().len();
        assert_eq!(amount_memory_oids, 9);
        assert_eq!(amount_memory_oids, amount_file_oids);
    }

    #[tokio::test]
    async fn file_storage_test() {
        let mut scans = Vec::with_capacity(100);
        for i in 0..100 {
            let scan = Scan {
                scan_id: i.to_string(),
                ..Default::default()
            };
            scans.push(scan);
        }

        let storage = example_feed_file_storage("/tmp/openvasd/file_storage_test").await;
        for s in scans.clone().into_iter() {
            storage.insert_scan(s).await.unwrap()
        }

        for s in scans.clone().into_iter() {
            let r = storage.get_scan(&s.scan_id).await;
            r.unwrap();
        }
        storage.remove_scan("5").await.unwrap();
        storage.insert_scan(scans[5].clone()).await.unwrap();
        let ids = storage.get_scan_ids().await.unwrap();
        assert_eq!(scans.len(), ids.len());
        let status = Status::default();
        let results = vec![models::Result::default()];
        let results = ScanResults {
            id: "42".to_string(),
            status,
            results,
        };
        storage
            .append_fetched_result(ScanResultKind::StatusOverride, results)
            .await
            .unwrap();

        let status = Status {
            status: Phase::Running,
            ..Default::default()
        };

        let results = vec![models::Result::default()];
        let results = ScanResults {
            id: "42".to_string(),
            status: status.clone(),
            results,
        };
        storage
            .append_fetched_result(ScanResultKind::StatusOverride, results)
            .await
            .unwrap();

        let stored_status = storage.get_status("42").await.unwrap();
        assert_eq!(status, stored_status);
        let range: Vec<String> = storage
            .get_results("42", None, None)
            .await
            .unwrap()
            .map(String::from_utf8)
            .filter_map(|x| x.ok())
            .collect();
        assert_eq!(2, range.len());
        for s in scans {
            let _ = storage.remove_scan(&s.scan_id).await;
        }

        let ids = storage.get_scan_ids().await.unwrap();
        assert_eq!(0, ids.len());
    }

    #[tokio::test]
    async fn id_mapper() {
        let storage = example_feed_file_storage("/tmp/openvasd/file_storage_id_mapper_test").await;
        storage
            .generate_mapped_id("0".into(), "s1".to_owned())
            .await
            .unwrap();
        let id = storage
            .generate_mapped_id("0".into(), "s2".to_owned())
            .await
            .unwrap();
        storage
            .generate_mapped_id("0".into(), "s3".to_owned())
            .await
            .unwrap();
        storage
            .generate_mapped_id("1".into(), "s4".to_owned())
            .await
            .unwrap();
        assert_eq!(
            storage.list_mapped_scan_ids(&"0".into()).await.unwrap(),
            vec!["s1", "s2", "s3"]
        );
        assert_eq!(
            storage.list_mapped_scan_ids(&"1".into()).await.unwrap(),
            vec!["s4"]
        );
        storage.remove_mapped_id(&id).await.unwrap();
        assert_eq!(
            storage.list_mapped_scan_ids(&"0".into()).await.unwrap(),
            vec!["s1", "s3"]
        );
        assert_eq!(
            storage.get_mapped_id(&"0".into(), "s1").await.unwrap(),
            "s1",
        );
        assert_eq!(
            storage.get_mapped_id(&"1".into(), "s4").await.unwrap(),
            "s4"
        );

        let mut storage = scannerlib::storage::infisto::IndexedFileStorer::init(
            "/tmp/openvasd/file_storage_id_mapper_test",
        )
        .unwrap();
        let key = "idmap";
        storage.remove(key).unwrap();
    }
}
