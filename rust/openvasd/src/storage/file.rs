use std::{ops::Deref, path::Path};

use super::*;

pub struct Storage<S> {
    storage: Arc<std::sync::RwLock<S>>,
    // although that will be lost on restart I will be read into immediately on start by parsing
    // the feed.
    hash: tokio::sync::RwLock<String>,
}
pub fn unencrypted<P>(path: P) -> Result<Storage<infisto::base::IndexedFileStorer>, Error>
where
    P: AsRef<Path>,
{
    let ifs = infisto::base::IndexedFileStorer::init(path)?;
    Ok(ifs.into())
}

pub fn encrypted<P, K>(
    path: P,
    key: K,
) -> Result<
    Storage<infisto::crypto::ChaCha20IndexFileStorer<infisto::base::IndexedFileStorer>>,
    Error,
>
where
    P: AsRef<Path>,
    K: Into<infisto::crypto::Key>,
{
    let ifs = infisto::base::IndexedFileStorer::init(path)?;
    Ok(infisto::crypto::ChaCha20IndexFileStorer::new(ifs, key).into())
}

impl From<infisto::base::Error> for Error {
    fn from(e: infisto::base::Error) -> Self {
        Self::Storage(Box::new(e))
    }
}

impl<S> From<S> for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + 'static,
{
    fn from(value: S) -> Self {
        Storage::new(value)
    }
}

impl<S> Storage<S> {
    pub fn new(s: S) -> Self {
        Storage {
            storage: Arc::new(s.into()),
            hash: tokio::sync::RwLock::new(String::new()),
        }
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
    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
        let key = format!("scan_{id}");
        let status_key = format!("status_{id}");

        let storage = Arc::clone(&self.storage);

        use infisto::base::Range;
        use infisto::bincode::Serialization;
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
        use infisto::bincode::Serialization;
        tokio::task::spawn_blocking(move || {
            let storage = &storage.read().unwrap();
            let scans: Vec<Serialization<String>> = match storage.by_range("scans", Range::All) {
                Ok(s) => s,
                Err(infisto::base::Error::FileOpen(std::io::ErrorKind::NotFound)) => vec![],
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
        use infisto::bincode::Serialization;
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
    async fn append_fetched_result(
        &self,
        id: &str,
        (status, results): FetchResult,
    ) -> Result<(), Error> {
        let key = format!("results_{}", id);
        self.update_status(id, status).await?;

        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || {
            let storage = &mut storage.write().unwrap();
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
            Ok(())
        })
        .await
        .unwrap()
    }
}
#[async_trait]
impl<S> ScanStorer for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn insert_scan(&self, scan: models::Scan) -> Result<(), Error> {
        let id = scan.scan_id.clone().unwrap_or_default();
        let key = format!("scan_{id}");
        let status_key = format!("status_{id}");
        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || {
            let scan = infisto::bincode::Serialization::serialize(scan)?;
            let status = infisto::bincode::Serialization::serialize(models::Status::default())?;
            let mut storage = storage.write().unwrap();
            storage.put(&key, scan)?;
            storage.put(&status_key, status)?;

            let stored_key = infisto::bincode::Serialization::serialize(&id)?;
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
            .filter_map(|x| infisto::bincode::Serialization::serialize(x).ok())
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
            let status = infisto::bincode::Serialization::serialize(status)?;
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
                .map(infisto::serde::Serialization::serialize)
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
impl<S> OIDStorer for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn push_oids(&self, hash: String, oids: Vec<String>) -> Result<(), Error> {
        let key = "oids".to_string();
        let storage = Arc::clone(&self.storage);
        let mut h = self.hash.write().await;
        *h = hash;

        tokio::task::spawn_blocking(move || {
            let oids = oids
                .into_iter()
                .filter_map(|x| infisto::bincode::Serialization::serialize(x.to_string()).ok())
                .collect::<Vec<_>>();

            let mut storage = storage.write().unwrap();
            match storage.remove(&key) {
                Ok(_) => {}
                Err(infisto::base::Error::Remove(std::io::ErrorKind::NotFound)) => {}
                Err(e) => return Err(e.into()),
            };
            storage.append_all(&key, &oids)?;
            Ok(())
        })
        .await
        .unwrap()
    }

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        let key = "oids".to_string();
        let storage = &self.storage.read().unwrap();
        let storage: S = storage.deref().clone();
        let iter = infisto::base::IndexedByteStorageIterator::<
            _,
            infisto::bincode::Serialization<String>,
        >::new(&key, storage)?;
        let parsed = iter
            .filter_map(|x| x.ok())
            .filter_map(|x| x.deserialize().ok());
        Ok(Box::new(parsed))
    }

    async fn feed_hash(&self) -> String {
        self.hash.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use infisto::base::IndexedByteStorage;
    use models::Scan;

    use super::*;

    #[test]
    fn serialize() {
        let scan = models::Status::default();

        let serialized = bincode::serialize(&scan).unwrap();
        let deserialized = bincode::deserialize(&serialized).unwrap();
        assert_eq!(scan, deserialized);
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
        scan.scan_id = Some("aha".to_string());
        let storage =
            infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/credential").unwrap();
        let storage = crate::storage::file::Storage::new(storage);
        storage.insert_scan(scan.clone()).await.unwrap();
        let (scan2, _) = storage.get_scan("aha").await.unwrap();
        assert_eq!(scan, scan2);
    }

    #[tokio::test]
    async fn oids() {
        let mut oids = Vec::with_capacity(100000);
        for i in 0..(oids.capacity()) {
            oids.push(i.to_string());
        }
        let storage = infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/oids").unwrap();
        let storage = crate::storage::file::Storage::new(storage);
        storage
            .push_oids(String::new(), oids.clone())
            .await
            .unwrap();
        let noids = storage.oids().await.unwrap();
        let mut len = 0;
        for (i, s) in noids.enumerate() {
            assert_eq!(s, oids[i]);
            len += 1;
        }
        assert_eq!(len, oids.len());
    }

    #[tokio::test]
    async fn file_storage_test() {
        let mut scans = Vec::with_capacity(100);
        for i in 0..100 {
            let scan = Scan {
                scan_id: Some(i.to_string()),
                ..Default::default()
            };
            scans.push(scan);
        }

        let storage =
            infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/file_storage_test").unwrap();
        let storage = crate::storage::file::Storage::new(storage);
        for s in scans.clone().into_iter() {
            storage.insert_scan(s).await.unwrap()
        }

        for s in scans.clone().into_iter() {
            storage.get_scan(&s.scan_id.unwrap()).await.unwrap();
        }
        storage.remove_scan("5").await.unwrap();
        storage.insert_scan(scans[5].clone()).await.unwrap();
        let ids = storage.get_scan_ids().await.unwrap();
        assert_eq!(scans.len(), ids.len());
        let status = models::Status::default();
        let results = vec![models::Result::default()];
        storage
            .append_fetched_result("42", (status, results))
            .await
            .unwrap();

        let status = models::Status {
            status: models::Phase::Running,
            ..Default::default()
        };

        let results = vec![models::Result::default()];
        storage
            .append_fetched_result("42", (status.clone(), results))
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
            let _ = storage.remove_scan(&s.scan_id.unwrap_or_default()).await;
        }

        let ids = storage.get_scan_ids().await.unwrap();
        assert_eq!(0, ids.len());
    }

    #[tokio::test]
    async fn id_mapper() {
        let storage =
            infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/file_storage_id_mapper_test")
                .unwrap();

        let storage = crate::storage::file::Storage::new(storage);
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
