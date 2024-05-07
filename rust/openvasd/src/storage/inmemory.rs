// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashSet;

use super::*;
use nasl_interpreter::FSPluginLoader;
use notus::loader::{hashsum::HashsumAdvisoryLoader, AdvisoryLoader};
use storage::item::{ItemDispatcher, Nvt, PerItemDispatcher};
use tokio::{sync::RwLock, task::JoinSet};

#[derive(Clone, Debug, Default)]
struct Progress {
    /// The scan that is being tracked. The credentials passwords are encrypted.
    scan: models::Scan,
    /// The status of the scan. Does not need to be encrypted.
    status: models::Status,
    /// The results of the scan as encrypted json.
    ///
    /// The reason that it is json is that we don't need it unless it is requested by the user.
    results: Vec<crypt::Encrypted>,
}

#[derive(Debug)]
pub struct Storage<E> {
    scans: RwLock<HashMap<String, Progress>>,
    nvts: Arc<RwLock<HashSet<Nvt>>>,
    feed_version: Arc<RwLock<String>>,
    hash: RwLock<Vec<FeedHash>>,
    client_id: RwLock<Vec<(ClientHash, String)>>,
    crypter: E,
}

struct Dispa {
    nvts: Arc<RwLock<HashSet<Nvt>>>,
    feed_version: Arc<RwLock<String>>,
}

impl ItemDispatcher<String> for Dispa {
    fn dispatch_nvt(&self, nvt: Nvt) -> Result<(), storage::StorageError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("Expected to be able to build a thread");
        rt.block_on(async {
            let mut nvts = self.nvts.write().await;
            nvts.insert(nvt);
        });
        Ok(())
    }

    fn dispatch_feed_version(&self, version: String) -> Result<(), storage::StorageError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("Expected to be able to build a thread");
        rt.block_on(async {
            let mut feed_version = self.feed_version.write().await;
            *feed_version = version;
        });
        Ok(())
    }

    fn dispatch_advisory(
        &self,
        _: &str,
        x: Box<Option<storage::NotusAdvisory>>,
    ) -> Result<(), storage::StorageError> {
        if let Some(x) = *x {
            let nvt: Nvt = x.into();
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("Expected to be able to build a thread");
            rt.block_on(async {
                let mut nvts = self.nvts.write().await;
                nvts.insert(nvt);
            });
        }
        Ok(())
    }
}

impl<E> Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    pub fn new(crypter: E, feeds: Vec<FeedHash>) -> Self {
        Self {
            scans: RwLock::new(HashMap::new()),
            nvts: Arc::new(RwLock::new(HashSet::with_capacity(100000))),
            hash: RwLock::new(feeds),
            client_id: RwLock::new(vec![]),
            crypter,
            feed_version: Arc::new(RwLock::new(String::new())),
        }
    }

    async fn new_progress(&self, mut scan: models::Scan) -> Result<Progress, Error> {
        let credentials = scan
            .target
            .credentials
            .into_iter()
            .map(move |c| {
                let c = c.map_password::<_, Error>(|p| {
                    Ok(self.crypter.encrypt_sync(p.as_bytes().to_vec()).to_string())
                });
                c.unwrap()
            })
            .collect::<Vec<_>>();
        scan.target.credentials = credentials;

        Ok(Progress {
            scan,
            status: models::Status::default(),
            results: Vec::new(),
        })
    }
}

impl Default for Storage<crate::crypt::ChaCha20Crypt> {
    fn default() -> Self {
        Self::new(
            crate::crypt::ChaCha20Crypt::default(),
            vec![
                FeedHash::nasl("/var/lib/openvas/feed"),
                FeedHash::advisories("/var/lib/notus/feed"),
            ],
        )
    }
}

#[async_trait]
impl<E> ScanIDClientMapper for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn add_scan_client_id(
        &self,
        scan_id: String,
        client_id: ClientHash,
    ) -> Result<(), Error> {
        let mut ids = self.client_id.write().await;
        ids.push((client_id, scan_id));

        Ok(())
    }

    async fn remove_scan_id<I>(&self, scan_id: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send + 'static,
    {
        let mut ids = self.client_id.write().await;
        let ssid = scan_id.as_ref();
        let mut to_remove = vec![];
        for (i, (_, sid)) in ids.iter().enumerate() {
            if sid == ssid {
                to_remove.push(i);
            }
        }
        for i in to_remove {
            ids.remove(i);
        }

        Ok(())
    }

    async fn get_scans_of_client_id(&self, client_id: &ClientHash) -> Result<Vec<String>, Error> {
        let ids = self.client_id.read().await;
        Ok(ids
            .iter()
            .filter(|(cid, _)| cid == client_id)
            .map(|(_, s)| s.to_owned())
            .collect())
    }
}
#[async_trait]
impl<E> ScanStorer for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn insert_scan(&self, sp: models::Scan) -> Result<(), Error> {
        let id = sp.scan_id.clone();
        let mut scans = self.scans.write().await;
        if let Some(prgs) = scans.get_mut(&id) {
            prgs.scan = sp;
        } else {
            let progress = self.new_progress(sp).await?;
            scans.insert(id.clone(), progress);
        }
        Ok(())
    }

    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        let mut scans = self.scans.write().await;

        scans.remove(id);
        Ok(())
    }

    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error> {
        let mut scans = self.scans.write().await;
        let progress = scans.get_mut(id).ok_or(Error::NotFound)?;
        progress.status = status;
        Ok(())
    }
}

#[async_trait]
impl<E> AppendFetchResult for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn append_fetched_result(&self, results: Vec<ScanResults>) -> Result<(), Error> {
        let mut scans = self.scans.write().await;
        for r in results {
            let id = &r.id;
            let progress = scans.get_mut(id).ok_or(Error::NotFound)?;
            progress.status = r.status;
            let mut len = progress.results.len();
            let results = r.results;
            for mut result in results {
                result.id = len;
                len += 1;
                let bytes = serde_json::to_vec(&result)?;
                progress.results.push(self.crypter.encrypt(bytes).await);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<E> ProgressGetter for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn get_scan_ids(&self) -> Result<Vec<String>, Error> {
        let scans = self.scans.read().await;
        let mut result = Vec::with_capacity(scans.len());
        for (_, progress) in scans.iter() {
            result.push(progress.scan.scan_id.clone());
        }
        Ok(result)
    }

    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
        let scans = self.scans.read().await;
        let progress = scans.get(id).ok_or(Error::NotFound)?;
        Ok((progress.scan.clone(), progress.status.clone()))
    }
    async fn get_decrypted_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
        let (mut scan, status) = self.get_scan(id).await?;
        let mut decrypted_credentials = Vec::with_capacity(scan.target.credentials.len());
        for c in scan.target.credentials.into_iter() {
            let c = c.map_password::<_, Error>(|p| {
                let enc = p.try_into()?;
                let dec = self.crypter.decrypt_sync(&enc);
                Ok(String::from_utf8(dec)?)
            })?;
            decrypted_credentials.push(c);
        }
        scan.target.credentials = decrypted_credentials;

        Ok((scan, status))
    }
    async fn get_status(&self, id: &str) -> Result<models::Status, Error> {
        let scans = self.scans.read().await;
        let progress = scans.get(id).ok_or(Error::NotFound)?;
        Ok(progress.status.clone())
    }
    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        let scans = self.scans.read().await;
        let progress = scans.get(id).ok_or(Error::NotFound)?;
        let from = from.unwrap_or(0);
        let to = to.unwrap_or(progress.results.len());
        let to = to.min(progress.results.len());
        if from > to || from > progress.results.len() {
            return Ok(Box::new(Vec::new().into_iter()));
        }
        let mut results = Vec::with_capacity(to - from);
        for result in &progress.results[from..to] {
            let b = self.crypter.decrypt_sync(result);
            results.push(b);
        }
        Ok(Box::new(results.into_iter()))
    }
}

impl From<feed::VerifyError> for Error {
    fn from(value: feed::VerifyError) -> Self {
        Error::Storage(Box::new(value))
    }
}
impl From<feed::UpdateError> for Error {
    fn from(value: feed::UpdateError) -> Self {
        Error::Storage(Box::new(value))
    }
}
impl From<notus::error::Error> for Error {
    fn from(value: notus::error::Error) -> Self {
        Error::Storage(Box::new(value))
    }
}

impl<E> Storage<E>
where
    E: Send + Sync + 'static,
{
    async fn update_notus_feed(p: PathBuf, nvts: Arc<RwLock<HashSet<Nvt>>>) -> Result<(), Error> {
        let notus_advisories_path = p;

        tokio::task::spawn_blocking(move || {
            tracing::debug!("starting notus feed update");
            let loader = FSPluginLoader::new(notus_advisories_path);
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

                    let rt = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .expect("Expected to be able to build a thread");
                    rt.block_on(async {
                        let mut nvts = nvts.write().await;
                        nvts.insert(nvt);
                    });
                }
            }
            tracing::debug!("finished notus feed update");
            Ok(())
        })
        .await
        .expect("notus handler to be executed.")
    }

    async fn update_nasl_feed(
        p: PathBuf,
        nvts: Arc<RwLock<HashSet<Nvt>>>,
        feed_version: Arc<RwLock<String>>,
    ) -> Result<(), Error> {
        let nasl_feed_path = p;

        tokio::task::spawn_blocking(move || {
            tracing::debug!("starting nasl feed update");
            let oversion = "0.1";
            let loader = FSPluginLoader::new(nasl_feed_path);
            let verifier = feed::HashSumNameLoader::sha256(&loader)?;

            let store = PerItemDispatcher::new(Dispa { nvts, feed_version });
            let mut fu = feed::Update::init(oversion, 5, loader.clone(), store, verifier);
            if let Some(x) = fu.find_map(|x| x.err()) {
                Err(Error::from(x))
            } else {
                tracing::debug!("finished nasl feed update");
                Ok(())
            }
        })
        .await
        .expect("nasl feed handler to be executed.")
    }
}

#[async_trait]
impl<E> NVTStorer for Storage<E>
where
    E: Send + Sync + 'static,
{
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        tracing::debug!("starting feed update");

        {
            let mut h = self.hash.write().await;
            for ha in h.iter_mut() {
                if let Some(nh) = hash.iter().find(|x| x.typus == ha.typus) {
                    ha.hash.clone_from(&nh.hash)
                }
            }
        }

        let mut updates = JoinSet::new();
        for h in hash {
            let path = h.path;
            match h.typus {
                FeedType::NASL => {
                    _ = updates.spawn(Self::update_nasl_feed(
                        path,
                        self.nvts.clone(),
                        self.feed_version.clone(),
                    ))
                }
                FeedType::Advisories => {
                    _ = updates.spawn(Self::update_notus_feed(path, self.nvts.clone()))
                }
                FeedType::Products => {}
            };
        }
        while let Some(f) = updates.join_next().await {
            f.unwrap()?
        }

        tracing::debug!("finished feed update.");

        Ok(())
    }

    async fn vts<'a>(
        &self,
    ) -> Result<Box<dyn Iterator<Item = storage::item::Nvt> + Send + 'a>, Error> {
        let o = self.nvts.read().await.clone().into_iter();
        Ok(Box::new(o))
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.hash.read().await.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use models::Scan;

    use super::*;

    #[tokio::test]
    async fn id_mapper() {
        let storage = Storage::default();
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
    }

    #[tokio::test]
    async fn store_delete_scan() {
        let storage = Storage::default();
        let scan = Scan::default();
        let id = scan.scan_id.clone();
        storage.insert_scan(scan).await.unwrap();
        let (retrieved, _) = storage.get_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id, id);
        storage.remove_scan(&id).await.unwrap();
    }

    #[tokio::test]
    async fn encrypt_decrypt_passwords() {
        let storage = Storage::default();
        let mut scan = Scan::default();
        let pw = models::Credential {
            credential_type: models::CredentialType::UP {
                username: "test".to_string(),
                password: "test".to_string(),
                privilege: None,
            },
            ..Default::default()
        };

        scan.target.credentials = vec![pw];

        let id = scan.scan_id.clone();
        storage.insert_scan(scan).await.unwrap();
        let (retrieved, _) = storage.get_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id, id);
        assert_ne!(retrieved.target.credentials[0].password(), "test");

        let (retrieved, _) = storage.get_decrypted_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id, id);
        assert_eq!(retrieved.target.credentials[0].password(), "test");
    }

    async fn store_scan(storage: &Storage<crypt::ChaCha20Crypt>) -> String {
        let mut scan = Scan::default();
        let id = uuid::Uuid::new_v4().to_string();
        scan.scan_id.clone_from(&id);
        storage.insert_scan(scan).await.unwrap();
        id
    }

    #[tokio::test]
    async fn get_scans() {
        let storage = Storage::default();
        for _ in 0..10 {
            store_scan(&storage).await;
        }
        let scans = storage.get_scan_ids().await.unwrap();
        assert_eq!(scans.len(), 10);
    }

    #[tokio::test]
    async fn append_results() {
        let storage = Storage::default();
        let scan = Scan::default();
        let id = scan.scan_id.clone();
        storage.insert_scan(scan).await.unwrap();
        let fetch_result = ScanResults {
            id: id.clone(),
            status: models::Status::default(),
            results: vec![models::Result::default()],
        };
        storage
            .append_fetched_result(vec![fetch_result])
            .await
            .unwrap();
        let results: Vec<_> = storage
            .get_results(&id, None, None)
            .await
            .unwrap()
            .collect();
        assert_eq!(results.len(), 1);

        let result: models::Result = serde_json::from_slice(&results[0]).unwrap();
        assert_eq!(result, models::Result::default());
        let results = storage.get_results(&id, Some(23), Some(1)).await.unwrap();
        assert_eq!(results.count(), 0);
        let results = storage.get_results(&id, Some(0), Some(0)).await.unwrap();
        assert_eq!(results.count(), 0);
        let results = storage.get_results(&id, Some(0), Some(5)).await.unwrap();
        assert_eq!(results.count(), 1);
        let results = storage.get_results(&id, Some(0), None).await.unwrap();
        assert_eq!(results.count(), 1);
    }

    #[tokio::test]
    async fn update_status() {
        let storage = Storage::default();
        let id = store_scan(&storage).await;
        let (_, mut status) = storage.get_scan(&id).await.unwrap();
        assert_eq!(status.status, models::Phase::Stored);
        status.status = models::Phase::Requested;
        storage.update_status(&id, status).await.unwrap();
        let (_, status) = storage.get_scan(&id).await.unwrap();
        assert_eq!(status.status, models::Phase::Requested);
    }
}
