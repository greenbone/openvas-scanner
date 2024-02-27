use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use nasl_interpreter::FSPluginLoader;
use notus::loader::{hashsum::HashsumAdvisoryLoader, AdvisoryLoader};
use storage::item::{ItemDispatcher, Nvt, PerItemDispatcher};

use super::*;

pub struct Storage<S> {
    hash: tokio::sync::RwLock<String>,
    nasl_feed_path: Arc<PathBuf>,
    notus_feed_path: Arc<PathBuf>,
    storage: Arc<std::sync::RwLock<S>>,
    feed_version: Arc<std::sync::RwLock<String>>,
}
pub fn unencrypted<P>(
    path: P,
    nasl_feed_path: P,
    notus_feed_path: P,
) -> Result<Storage<infisto::base::IndexedFileStorer>, Error>
where
    P: AsRef<Path>,
{
    let ifs = infisto::base::IndexedFileStorer::init(path)?;
    Ok(Storage::new(ifs, nasl_feed_path, notus_feed_path))
}

pub fn encrypted<P, K>(
    path: P,
    key: K,
    nasl_feed_path: P,
    notus_feed_path: P,
) -> Result<
    Storage<infisto::crypto::ChaCha20IndexFileStorer<infisto::base::IndexedFileStorer>>,
    Error,
>
where
    P: AsRef<Path>,
    K: Into<infisto::crypto::Key>,
{
    let ifs = infisto::base::IndexedFileStorer::init(path)?;
    let ifs = infisto::crypto::ChaCha20IndexFileStorer::new(ifs, key);
    Ok(Storage::new(ifs, nasl_feed_path, notus_feed_path))
}

impl From<infisto::base::Error> for Error {
    fn from(e: infisto::base::Error) -> Self {
        Self::Storage(Box::new(e))
    }
}

impl<S> Storage<S> {
    pub fn new<P>(s: S, nasl_feed_path: P, notus_feed_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Storage {
            storage: Arc::new(s.into()),
            hash: tokio::sync::RwLock::new(String::new()),
            nasl_feed_path: Arc::new(nasl_feed_path.as_ref().to_path_buf()),
            notus_feed_path: Arc::new(notus_feed_path.as_ref().to_path_buf()),

            feed_version: Arc::new(std::sync::RwLock::new(String::new())),
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

struct Dispa {
    storage: Arc<std::sync::RwLock<HashMap<String, Nvt>>>,
    feed_version: Arc<std::sync::RwLock<String>>,
}

impl ItemDispatcher<String> for Dispa {
    fn dispatch_nvt(&self, nvt: Nvt) -> Result<(), storage::StorageError> {
        let mut storage = self.storage.write().unwrap();
        let oid = nvt.oid.clone();
        storage.insert(oid, nvt);
        Ok(())
    }

    fn dispatch_feed_version(&self, version: String) -> Result<(), storage::StorageError> {
        let mut feed_version = self.feed_version.write().unwrap();
        *feed_version = version;
        Ok(())
    }

    fn dispatch_advisory(
        &self,
        _: &str,
        _: Box<Option<storage::NotusAdvisory>>,
    ) -> Result<(), storage::StorageError> {
        Ok(())
    }
}

pub const FEED_KEY: &str = "nvts";

#[async_trait]
impl<S> NVTStorer for Storage<S>
where
    S: infisto::base::IndexedByteStorage + std::marker::Sync + std::marker::Send + Clone + 'static,
{
    async fn synchronize_feeds(&self, hash: String) -> Result<(), Error> {
        let mut h = self.hash.write().await;
        *h = hash;
        drop(h);

        tracing::debug!("starting feed update in file {}", &FEED_KEY);
        let storage = Arc::clone(&self.storage);
        // we cache them upfront to avoid deletion and faster storage
        let nvts = Arc::new(std::sync::RwLock::new(HashMap::with_capacity(100000)));
        let notus_feed_path = self.notus_feed_path.clone();
        let feed_version = self.feed_version.clone();
        let nasl_feed_path = self.nasl_feed_path.clone();

        let tnvts = nvts.clone();
        let notus_feed = tokio::task::spawn_blocking(move || {
            tracing::debug!("starting notus feed update");
            let loader = FSPluginLoader::new(notus_feed_path.as_ref());
            let advisories_files = HashsumAdvisoryLoader::new(loader.clone())?;

            for filename in advisories_files.get_advisories()?.iter() {
                let advisories = advisories_files.load_advisory(filename)?;

                for adv in advisories.advisories {
                    let data = models::VulnerabilityData {
                        adv,
                        famile: advisories.family.clone(),
                        filename: filename.to_owned(),
                    };
                    let nvt: Nvt = data.into();
                    let mut storage = tnvts.write().unwrap();
                    storage.insert(nvt.oid.clone(), nvt);

                    drop(storage);
                }
            }
            tracing::debug!("finished notus feed update");
            Ok::<_, Error>(())
        });
        let tnvts = nvts.clone();

        let active_feed = tokio::task::spawn_blocking(move || {
            tracing::debug!("starting nasl feed update");
            let oversion = "0.1";
            let loader = FSPluginLoader::new(nasl_feed_path.as_ref());
            let verifier = feed::HashSumNameLoader::sha256(&loader)?;

            let store = PerItemDispatcher::new(Dispa {
                storage: tnvts,
                feed_version,
            });
            let mut fu = feed::Update::init(oversion, 5, loader.clone(), store, verifier);
            if let Some(x) = fu.find_map(|x| x.err()) {
                tracing::debug!("{}", x);
                Err(Error::from(x))
            } else {
                tracing::debug!("finished nasl feed update");
                Ok(())
            }
        });

        let nasl_result = active_feed.await.unwrap();
        let notus_result: Result<(), Error> = notus_feed.await.unwrap();
        let tnvts = nvts.clone();
        tokio::task::spawn_blocking(move || {
            let mut storage = storage.write().expect("storage seems to be poisoned");
            let _ = storage.remove(FEED_KEY);
            let tnvts = tnvts.read().unwrap();
            let srs = tnvts
                .values()
                .filter_map(|x| infisto::serde::Serialization::serialize(x).ok())
                .collect::<Vec<_>>();

            tracing::debug!("writing stuff {}", srs.len());
            storage.append_all(FEED_KEY, &srs)?;
            tracing::debug!("ahah");
            Ok::<_, Error>(())
        })
        .await
        .unwrap()?;
        tracing::debug!("finished feed update");

        match (nasl_result, notus_result) {
            (Ok(_), Ok(_)) => Ok(()),
            (Ok(_), Err(err)) => Err(err),
            (Err(err), Ok(_)) => Err(err),
            (Err(err), Err(_)) => Err(err),
        }
    }

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        let storage = &self.storage.read().unwrap();
        let storage: S = storage.deref().clone();
        let iter = infisto::base::IndexedByteStorageIterator::<
            _,
            infisto::serde::Serialization<Nvt>,
        >::new(FEED_KEY, storage)?;
        let parsed = iter
            .filter_map(|x| x.ok())
            .filter_map(|x| x.deserialize().ok())
            .map(|x| x.oid);

        Ok(Box::new(parsed))
    }

    async fn vts<'a>(
        &self,
    ) -> Result<Box<dyn Iterator<Item = storage::item::Nvt> + Send + 'a>, Error> {
        let storage = &self.storage.read().unwrap();
        let storage: S = storage.deref().clone();
        let iter = infisto::base::IndexedByteStorageIterator::<
            _,
            infisto::serde::Serialization<Nvt>,
        >::new(FEED_KEY, storage)?;
        let parsed = iter.map(|x| x.unwrap()).map(|x| x.deserialize().unwrap());
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
        let storage =
            infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/credential").unwrap();
        let nfp = "../../examples/feed/nasl";
        let nofp = "../../examples/feed/notus/advisories";
        let storage = crate::storage::file::Storage::new(storage, nfp, nofp);
        storage.insert_scan(scan.clone()).await.unwrap();
        let (scan2, _) = storage.get_scan("aha").await.unwrap();
        assert_eq!(scan, scan2);
    }

    #[tokio::test]
    async fn oids() {
        let storage = infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/oids").unwrap();

        let base = std::env::current_dir().unwrap_or_default();

        let mut tbase = base.parent().unwrap().join("examples");
        if std::fs::metadata(&tbase).is_err() {
            tbase = base.join("examples");
        }
        let base_dir = tbase.join("feed");

        let nfp = base_dir.join("nasl");
        let nofp = base_dir.join("notus").join("advisories");
        let file_storage = crate::storage::file::Storage::new(storage, &nfp, &nofp);
        file_storage
            .synchronize_feeds("123".to_string())
            .await
            .unwrap();
        let amount_file_oids = file_storage.oids().await.unwrap().count();

        let mut storage = infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/oids").unwrap();
        storage.remove(crate::storage::file::FEED_KEY).unwrap();
        let memory_storage = crate::storage::inmemory::Storage::new(
            crate::crypt::ChaCha20Crypt::default(),
            nfp,
            nofp,
        );
        memory_storage
            .synchronize_feeds("123".to_string())
            .await
            .unwrap();
        let amount_memory_oids = memory_storage.oids().await.unwrap().count();
        assert_eq!(amount_memory_oids, 2);
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

        let storage =
            infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/file_storage_test").unwrap();
        let nfp = "../../examples/feed/nasl";
        let nofp = "../../examples/feed/notus/advisories";
        let storage = crate::storage::file::Storage::new(storage, nfp, nofp);
        for s in scans.clone().into_iter() {
            storage.insert_scan(s).await.unwrap()
        }

        for s in scans.clone().into_iter() {
            storage.get_scan(&s.scan_id).await.unwrap();
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
        for s in scans {
            let _ = storage.remove_scan(&s.scan_id).await;
        }

        let ids = storage.get_scan_ids().await.unwrap();
        assert_eq!(0, ids.len());
    }

    #[tokio::test]
    async fn id_mapper() {
        let storage =
            infisto::base::CachedIndexFileStorer::init("/tmp/openvasd/file_storage_id_mapper_test")
                .unwrap();

        let nfp = "../../examples/feed/nasl";
        let nofp = "../../examples/feed/notus/advisories";
        let storage = crate::storage::file::Storage::new(storage, nfp, nofp);
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
