// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::RwLock;

use super::*;
use scannerlib::{
    models, notus,
    storage::{Retriever, inmemory::OIDs, items::nvt::Feed},
};
use tokio::task::JoinSet;

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
    scans: Arc<RwLock<HashMap<String, Progress>>>,
    hash: Arc<RwLock<Vec<FeedHash>>>,
    client_id: Arc<RwLock<Vec<(ClientHash, String)>>>,
    underlying: Arc<InMemoryStorage>,
    crypter: Arc<E>,
    feed_version: Arc<RwLock<String>>,
}

impl<E> Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    pub fn new(crypter: E, feeds: Vec<FeedHash>) -> Self {
        Self {
            scans: RwLock::new(HashMap::new()).into(),
            hash: RwLock::new(feeds).into(),
            client_id: RwLock::new(vec![]).into(),
            crypter: crypter.into(),
            underlying: InMemoryStorage::default().into(),
            feed_version: Arc::new(RwLock::new(String::new())),
        }
    }

    fn new_progress(crypter: &E, mut scan: models::Scan) -> Result<Progress, Error> {
        let credentials = scan
            .target
            .credentials
            .into_iter()
            .map(move |c| {
                let c = c.map_password::<_, Error>(|p| {
                    Ok(crypter.encrypt_sync(p.as_bytes().to_vec()).to_string())
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

    fn decrypt_results_sync(
        crypter: Arc<E>,
        progress: &Progress,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Box<dyn Iterator<Item = Vec<u8>> + Send> {
        let from = from.unwrap_or(0);
        let to = to.unwrap_or(progress.results.len());
        let to = to.min(progress.results.len());
        if from > to || from > progress.results.len() {
            return Box::new(Vec::new().into_iter());
        }
        let mut results = Vec::with_capacity(to - from);
        for result in &progress.results[from..to] {
            let b = crypter.decrypt_sync(result);
            results.push(b);
        }
        Box::new(results.into_iter())
    }

    fn get_results_sync(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        let scans = self.scans.read().unwrap();
        let progress = scans.get(id).ok_or(Error::NotFound)?;
        Ok(Self::decrypt_results_sync(
            self.crypter.clone(),
            progress,
            from,
            to,
        ))
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
    async fn generate_mapped_id(
        &self,
        client_id: ClientHash,
        scan_id: String,
    ) -> Result<MappedID, Error> {
        let mut ids = self.client_id.write().unwrap();
        ids.push((client_id, scan_id.clone()));

        Ok(scan_id)
    }

    async fn remove_mapped_id(&self, scan_id: &str) -> Result<(), Error> {
        let mut ids = self.client_id.write().unwrap();
        let mut to_remove = vec![];
        for (i, (_, sid)) in ids.iter().enumerate().rev() {
            if sid == scan_id {
                to_remove.push(i);
            }
        }

        for i in to_remove {
            ids.remove(i);
        }

        Ok(())
    }

    async fn list_mapped_scan_ids(&self, client_id: &ClientHash) -> Result<Vec<String>, Error> {
        let ids = self.client_id.read().unwrap();
        Ok(ids
            .iter()
            .filter(|(cid, _)| cid == client_id)
            .map(|(_, s)| s.to_owned())
            .collect())
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
}
#[async_trait]
impl<E> ScanStorer for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn insert_scan(&self, sp: models::Scan) -> Result<(), Error> {
        let scans = self.scans.clone();
        let crypter = self.crypter.clone();
        tokio::task::spawn_blocking(move || {
            let mut scans = scans.write().unwrap();
            let id = sp.scan_id.clone();
            match scans.get_mut(&id) {
                Some(prgs) => {
                    prgs.scan = sp;
                }
                _ => {
                    let progress = Self::new_progress(crypter.as_ref(), sp)?;
                    scans.insert(id.clone(), progress);
                }
            }
            Ok(())
        })
        .await
        .unwrap()
    }

    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        let mut scans = self.scans.write().unwrap();

        scans.remove(id);
        Ok(())
    }

    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error> {
        let mut scans = self.scans.write().unwrap();
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
    async fn append_fetched_result(
        &self,
        kind: ScanResultKind,
        mut r: ScanResults,
    ) -> Result<(), Error> {
        let scans = self.scans.clone();
        let crypter = self.crypter.clone();
        tokio::task::spawn_blocking(move || {
            let mut scans = scans.write().unwrap();
            let id = &r.id;
            let progress = scans.get_mut(id).ok_or(Error::NotFound)?;
            // maybe instead of progress.status = r.status we can set it to

            match kind {
                ScanResultKind::StatusOverride => progress.status = r.status,
                ScanResultKind::StatusAddition => {
                    // unfortunately the order plays a role
                    r.status.update_with(&progress.status);
                    progress.status = r.status;
                }
            };
            let mut len = progress.results.len();
            let results = r.results;
            for mut result in results {
                result.id = len;
                len += 1;
                let bytes = serde_json::to_vec(&result)?;
                progress.results.push(crypter.encrypt_sync(bytes));
            }
            Ok(())
        })
        .await
        .unwrap()
    }
}

#[async_trait]
impl<E> ProgressGetter for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn get_scan_ids(&self) -> Result<Vec<String>, Error> {
        let scans = self.scans.read().unwrap();
        let mut result = Vec::with_capacity(scans.len());
        for (_, progress) in scans.iter() {
            result.push(progress.scan.scan_id.clone());
        }
        Ok(result)
    }

    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
        let scans = self.scans.read().unwrap();
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
        let scans = self.scans.read().unwrap();
        let progress = scans.get(id).ok_or(Error::NotFound)?;
        Ok(progress.status.clone())
    }

    // TODO: figure out a way to get rid of send so that we can use await
    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        self.get_results_sync(id, from, to)
    }
}

impl<E> FromConfigAndFeeds for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static + Default,
{
    async fn from_config_and_feeds(
        _: &Config,
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(inmemory::Storage::new(E::default(), feeds))
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
impl From<notus::NotusError> for Error {
    fn from(value: notus::NotusError) -> Self {
        Error::Storage(Box::new(value))
    }
}

impl<E> Storage<E> where E: Send + Sync + 'static {}

#[async_trait]
impl<E> NVTStorer for Storage<E>
where
    E: Send + Sync + 'static,
{
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        tracing::debug!("starting feed update");

        {
            let mut h = self.hash.write().unwrap();
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
                    _ = updates.spawn(super::update_nasl_feed(path, self.underlying.clone()))
                }
                FeedType::Advisories => {
                    _ = updates.spawn(super::update_notus_feed(path, self.underlying.clone()))
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

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error> {
        self.underlying
            .retrieve(&scannerlib::storage::items::nvt::Oid(oid.to_string()))
            .map_err(|e| e.into())
    }

    async fn vts<'a>(&self) -> Result<Vec<Nvt>, Error> {
        let vts = self.underlying.retrieve(&Feed)?.unwrap_or_default();
        Ok(vts)
    }

    async fn oids(&self) -> Result<Vec<String>, Error> {
        let vts = self.underlying.retrieve(&OIDs)?.unwrap_or_default();
        Ok(vts)
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        self.hash.read().unwrap().to_vec()
    }

    async fn current_feed_version(&self) -> Result<String, Error> {
        let v = self.feed_version.read().unwrap();
        Ok(v.clone())
    }
}

impl<C> super::ResultHandler for Storage<C>
where
    C: crate::crypt::Crypt + Send + Sync + 'static,
{
    fn underlying_storage(&self) -> &Arc<InMemoryStorage> {
        &self.underlying
    }

    fn handle_result<E>(&self, key: &str, mut result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>,
    {
        // we may already run in an specialized thread therefore we use current thread.
        use models::Phase;
        let mut scans = self.scans.write().unwrap();
        let progress = scans
            .get_mut(key)
            .ok_or_else(|| StorageError::UnexpectedData(format!("Expected scan for {key}")))?;
        // Status fail safe when there is a bug
        match &progress.status.status {
            Phase::Stored | Phase::Requested => progress.status.status = Phase::Running,
            _ => {}
        };
        result.id = progress.results.len(); // fail safe

        let bytes = serde_json::to_vec(&result)
            .map_err(|e| StorageError::UnexpectedData(format!("{e}")))?;
        progress.results.push(self.crypter.encrypt_sync(bytes));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use models::Scan;
    use scannerlib::models::{Credential, CredentialType};

    use super::*;

    #[tokio::test]
    async fn id_mapper() {
        let storage = Storage::default();
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
    }

    fn password(c: &Credential) -> &str {
        match &c.credential_type {
            CredentialType::UP { password, .. }
            | CredentialType::SNMP { password, .. }
            | CredentialType::KRB5 { password, .. } => password,
            CredentialType::USK { password, .. } => match password {
                Some(p) => p,
                None => "",
            },
        }
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
                password: "pass".to_string(),
                privilege: None,
            },
            ..Default::default()
        };

        scan.target.credentials = vec![pw];

        let id = scan.scan_id.clone();
        storage.insert_scan(scan).await.unwrap();
        let (retrieved, _) = storage.get_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id, id);
        assert_ne!(password(&retrieved.target.credentials[0]), "pass");

        let (retrieved, _) = storage.get_decrypted_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id, id);
        assert_eq!(password(&retrieved.target.credentials[0]), "pass");
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
    async fn delete_results() {
        let storage = Storage::default();
        let scan = Scan::default();
        let id = scan.scan_id.clone();
        storage.insert_scan(scan).await.unwrap();
        let fetch_result = ScanResults {
            id: id.clone(),
            status: models::Status::default(),
            results: vec![
                models::Result::default(),
                models::Result::default(),
                models::Result::default(),
                models::Result::default(),
                models::Result::default(),
            ],
        };
        storage
            .append_fetched_result(ScanResultKind::StatusOverride, fetch_result)
            .await
            .unwrap();
        let results: Vec<_> = storage
            .get_results(&id, None, None)
            .await
            .unwrap()
            .collect();
        assert_eq!(results.len(), 5);
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
            .append_fetched_result(ScanResultKind::StatusOverride, fetch_result)
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
