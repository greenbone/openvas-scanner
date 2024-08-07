// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{ops::Deref, path::Path};

use infisto::{base::IndexedFileStorer, crypto::ChaCha20IndexFileStorer};
use tracing::{info, warn};

use super::*;

pub struct Storage<S> {
    storage: Arc<std::sync::RwLock<S>>,
    // we use inmemory for NVT and KB items as we need to continously when starting or running a
    // scan. KB items should be deleted when a scan is finished.
    underlying: super::inmemory::Storage<crypt::ChaCha20Crypt>,
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
    K: Into<infisto::crypto::Key>,
{
    let ifs = IndexedFileStorer::init(path)?;
    let ifs = ChaCha20IndexFileStorer::new(ifs, key);
    Ok(Storage::new(ifs, feeds))
}

impl From<infisto::Error> for Error {
    fn from(e: infisto::Error) -> Self {
        Self::Storage(Box::new(e))
    }
}

impl<S> Storage<S> {
    pub fn new(s: S, feeds: Vec<FeedHash>) -> Self {
        Storage {
            storage: Arc::new(s.into()),
            underlying: super::inmemory::Storage::new(
                crate::crypt::ChaCha20Crypt::default(),
                feeds,
            ),
        }
    }
}

impl<S> Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    fn get_results_sync(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        let range = {
            use infisto::base::Range;
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
        let iter = infisto::base::IndexedByteStorageIterator::<_, Vec<u8>>::by_range(
            &key, storage, range,
        )?;
        let parsed = iter.filter_map(|x| x.ok());
        Ok(Box::new(parsed))
    }
}

#[async_trait]
impl<S> ProgressGetter for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn get_decrypted_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
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
    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
        let key = format!("scan_{id}");
        let status_key = format!("status_{id}");

        let storage = Arc::clone(&self.storage);

        use infisto::base::Range;
        use infisto::serde::Serialization;
        tokio::task::spawn_blocking(move || {
            let storage = storage.read().unwrap();
            let scans: Vec<Serialization<models::Scan>> = storage.by_range(&key, Range::All)?;
            let status: Vec<Serialization<models::Status>> =
                storage.by_range(&status_key, Range::All)?;

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
        use infisto::base::Range;
        use infisto::serde::Serialization;
        tokio::task::spawn_blocking(move || {
            let storage = &storage.read().unwrap();
            let scans: Vec<Serialization<String>> = match storage.by_range("scans", Range::All) {
                Ok(s) => s,
                Err(infisto::Error::IoError(
                    infisto::IoErrorKind::FileOpen,
                    std::io::ErrorKind::NotFound,
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
    async fn get_status(&self, id: &str) -> Result<models::Status, Error> {
        let key = format!("status_{id}");
        let storage = Arc::clone(&self.storage);

        use infisto::base::Range;
        use infisto::serde::Serialization;
        tokio::task::spawn_blocking(move || {
            let storage = &storage.read().unwrap();
            let status: Vec<Serialization<models::Status>> = storage.by_range(&key, Range::All)?;
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
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error> {
        for r in results {
            let id = &r.id;
            let status = r.status;
            let key = format!("results_{}", id);
            self.update_status(id, status).await?;

            let storage = Arc::clone(&self.storage);
            tokio::task::spawn_blocking(move || {
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
            .unwrap()?
        }
        Ok(())
    }
}
#[async_trait]
impl<S> ScanStorer for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn insert_scan(&self, scan: models::Scan) -> Result<(), Error> {
        let id = scan.scan_id.clone();
        let key = format!("scan_{id}");
        let status_key = format!("status_{id}");
        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || {
            let scan = infisto::serde::Serialization::serialize(scan)?;
            let status = infisto::serde::Serialization::serialize(models::Status::default())?;
            let mut storage = storage.write().unwrap();
            storage.put(&key, scan)?;
            storage.put(&status_key, status)?;

            let stored_key = infisto::serde::Serialization::serialize(&id)?;
            storage.append("scans", stored_key)?;
            Ok(())
        })
        .await
        .unwrap()
    }
    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        let key = format!("scan_{}", id);
        let status_key = format!("status_{}", id);
        let results_key = format!("results_{}", id);
        let storage = Arc::clone(&self.storage);
        let ids = self.get_scan_ids().await?;
        let ids: Vec<_> = ids
            .into_iter()
            .filter(|x| x != id)
            .filter_map(|x| infisto::serde::Serialization::serialize(x).ok())
            .collect();

        tokio::task::spawn_blocking(move || {
            // we ignore results errors as there may or may not be results
            let mut storage = storage.write().unwrap();
            let _ = storage.remove(&results_key);
            storage.remove(&key)?;
            storage.remove(&status_key)?;
            storage.remove("scans")?;
            storage.append_all("scans", &ids)?;
            Ok(())
        })
        .await
        .unwrap()
    }
    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error> {
        let key = format!("status_{}", id);
        let storage = Arc::clone(&self.storage);

        tokio::task::spawn_blocking(move || {
            let status = infisto::serde::Serialization::serialize(status)?;
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
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn add_scan_client_id(
        &self,
        scan_id: String,
        client_id: ClientHash,
    ) -> Result<(), Error> {
        let key = "idmap";
        let storage = Arc::clone(&self.storage);

        tokio::task::spawn_blocking(move || {
            let idt = infisto::serde::Serialization::serialize((client_id, scan_id))?;
            let mut storage = storage.write().unwrap();
            storage.append(key, idt)?;
            Ok(())
        })
        .await
        .unwrap()
    }
    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let key = "idmap";
        let storage = Arc::clone(&self.storage);

        tokio::task::spawn_blocking(move || {
            use infisto::serde::Serialization;
            let mut storage = storage.write().unwrap();
            let sid = scan_id.as_ref();

            let ids: Vec<Serialization<(ClientHash, String)>> =
                storage.by_range(key, infisto::base::Range::All)?;
            let new: Vec<Serialization<(ClientHash, String)>> = ids
                .into_iter()
                .map(|x| x.deserialize())
                .filter_map(|x| x.ok())
                .filter(|(_, x)| x != sid)
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

    async fn get_scans_of_client_id(&self, client_id: &ClientHash) -> Result<Vec<String>, Error> {
        let key = "idmap";
        let storage = Arc::clone(&self.storage);
        let client_id = client_id.clone();

        tokio::task::spawn_blocking(move || {
            use infisto::serde::Serialization;
            let storage = storage.read().unwrap();

            let ids: Vec<Serialization<(ClientHash, String)>> =
                match storage.by_range(key, infisto::base::Range::All) {
                    Ok(x) => x,
                    Err(_) => vec![],
                };
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
}

#[async_trait]
impl<S> NVTStorer for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        self.underlying.synchronize_feeds(hash).await
    }

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        self.underlying.oids().await
    }

    async fn vts<'a>(
        &self,
    ) -> Result<Box<dyn Iterator<Item = storage::item::Nvt> + Send + 'a>, Error> {
        self.underlying.vts().await
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.underlying.feed_hash().await
    }
}

impl FromConfigAndFeeds for Storage<ChaCha20IndexFileStorer<IndexedFileStorer>> {
    fn from_config_and_feeds(
        config: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        info!("using in file storage. Sensitive data will be encrypted stored on disk.");
        // If this is even being called, we can assume we have a key
        let key = config.storage.fs.key.as_ref().unwrap();
        Ok(file::encrypted(&config.storage.fs.path, key, feeds)?)
    }
}

impl FromConfigAndFeeds for Storage<IndexedFileStorer> {
    fn from_config_and_feeds(
        config: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        warn!(
            "using in file storage. Sensitive data will be stored on disk without any encryption."
        );
        Ok(file::unencrypted(&config.storage.fs.path, feeds)?)
    }
}

impl<S> super::ResultHandler for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    fn underlying_storage(&self) -> &Arc<storage::DefaultDispatcher> {
        self.underlying.underlying_storage()
    }

    fn handle_result<E>(&self, key: &storage::ContextKey, result: models::Result) -> Result<(), E>
    where
        E: From<storage::StorageError>,
    {
        let store = &mut self.storage.write().unwrap();
        let key = format!("results_{}", key.value());

        let ilen = match store.indices(&key) {
            Ok(x) => x.len(),
            Err(_) => 0,
        };
        let results = vec![result];
        let mut serialized_results = Vec::with_capacity(results.len());
        for (i, mut result) in results.into_iter().enumerate() {
            result.id = ilen + i;
            let bytes = serde_json::to_vec(&result).map_err(|x| {
                storage::StorageError::UnexpectedData(format!("Unable to serialize results: {x}"))
            })?;
            serialized_results.push(bytes);
        }
        store
            .append_all(&key, &serialized_results)
            .map_err(|x| storage::StorageError::Dirty(format!("Unable to store to disk: {x}")))?;
        Ok(())
    }

    fn remove_result<E>(
        &self,
        key: &storage::ContextKey,
        idx: Option<usize>,
    ) -> Result<Vec<models::Result>, E>
    where
        E: From<storage::StorageError>,
    {
        let deleted_results = self
            .get_results_sync(key.as_ref(), idx, idx.map(|x| x + 1))
            .map_err(|x| storage::StorageError::Dirty(x.to_string()))?
            .filter_map(|x| serde_json::de::from_slice(&x).ok())
            .collect();
        if let Some(_idx) = idx {
            // is unsupported as then the result index wouldn't match tyhye file index anymore
            // which could have side effects for get results in the openvasd api as we store the
            // json as is.
            tracing::warn!("called an unsupported function to delete a result within the file storage, ignoring");
        } else {
            let key = format!("results_{}", key.value());
            let store = &mut self.storage.write().unwrap();
            store
                .remove(&key)
                .map_err(|_| storage::StorageError::NotFound(key))?;
        }
        Ok(deleted_results)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use infisto::base::IndexedByteStorage;
    use models::Scan;

    use super::*;

    /// Creates a Storage with a cached file storer based on the feed found `rust/examples/feed/`.
    pub async fn example_feed_file_storage(
        target: &str,
    ) -> Storage<infisto::base::CachedIndexFileStorer> {
        let storage = infisto::base::CachedIndexFileStorer::init(target).unwrap();
        let base = std::env::current_dir().unwrap_or_default();

        let mut tbase = base.parent().unwrap().join("examples");
        if std::fs::metadata(&tbase).is_err() {
            tbase = base.join("examples");
        }
        let base_dir = tbase.join("feed");

        let nfp = base_dir.join("nasl");
        let nofp = base_dir.join("notus").join("advisories");
        tracing::debug!(nasl_feed=?nfp, notus_advisories_feed=?nofp);
        crate::storage::file::Storage::new(
            storage,
            vec![FeedHash::nasl(nfp), FeedHash::advisories(nofp)],
        )
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
        let storage = example_feed_file_storage("/tmp/openvasd/credential").await;
        storage.insert_scan(scan.clone()).await.unwrap();
        let (scan2, _) = storage.get_scan("aha").await.unwrap();
        assert_eq!(scan, scan2);
    }

    #[tokio::test]
    async fn oids() {
        let file_storage = example_feed_file_storage("/tmp/openvasd/oids").await;
        let feeds = file_storage.feed_hash().await;
        file_storage.synchronize_feeds(feeds.clone()).await.unwrap();
        let amount_file_oids = file_storage.oids().await.unwrap().count();

        let memory_storage = crate::storage::inmemory::Storage::new(
            crate::crypt::ChaCha20Crypt::default(),
            feeds.clone(),
        );
        memory_storage.synchronize_feeds(feeds).await.unwrap();
        let amount_memory_oids = memory_storage.oids().await.unwrap().count();
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
        let status = models::Status::default();
        let results = vec![models::Result::default()];
        let results = vec![ScanResults {
            id: "42".to_string(),
            status,
            results,
        }];
        storage.append_fetched_result(results).await.unwrap();

        let status = models::Status {
            status: models::Phase::Running,
            ..Default::default()
        };

        let results = vec![models::Result::default()];
        let results = vec![ScanResults {
            id: "42".to_string(),
            status: status.clone(),
            results,
        }];
        storage.append_fetched_result(results).await.unwrap();
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
        let deleted_results = storage
            .remove_result::<Error>(&storage::ContextKey::Scan("42".to_string(), None), None)
            .unwrap();
        assert_eq!(deleted_results.len(), range.len());
        let range: Vec<String> = storage
            .get_results("42", None, None)
            .await
            .unwrap()
            .map(String::from_utf8)
            .filter_map(|x| x.ok())
            .collect();
        assert_eq!(0, range.len());

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
            .add_scan_client_id("s1".to_owned(), "0".into())
            .await
            .unwrap();
        storage
            .add_scan_client_id("s2".to_owned(), "0".into())
            .await
            .unwrap();
        storage
            .add_scan_client_id("s3".to_owned(), "0".into())
            .await
            .unwrap();
        storage
            .add_scan_client_id("s4".to_owned(), "1".into())
            .await
            .unwrap();
        assert_eq!(
            storage.get_scans_of_client_id(&"0".into()).await.unwrap(),
            vec!["s1", "s2", "s3"]
        );
        assert_eq!(
            storage.get_scans_of_client_id(&"1".into()).await.unwrap(),
            vec!["s4"]
        );
        storage.remove_scan_id("s2").await.unwrap();
        assert_eq!(
            storage.get_scans_of_client_id(&"0".into()).await.unwrap(),
            vec!["s1", "s3"]
        );
        assert!(!storage.is_client_allowed("s1", &"1".into()).await.unwrap());
        assert!(storage.is_client_allowed("s4", &"1".into()).await.unwrap());

        let mut storage =
            infisto::base::IndexedFileStorer::init("/tmp/openvasd/file_storage_id_mapper_test")
                .unwrap();
        let key = "idmap";
        storage.remove(key).unwrap();
    }
}
