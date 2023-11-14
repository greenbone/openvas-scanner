use super::*;
use tokio::sync::RwLock;

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
    oids: RwLock<Vec<String>>,
    hash: RwLock<String>,
    client_id: RwLock<Vec<(ClientHash, String)>>,

    crypter: E,
}

impl<E> Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    pub fn new(crypter: E) -> Self {
        Self {
            scans: RwLock::new(HashMap::new()),
            oids: RwLock::new(vec![]),
            hash: RwLock::new(String::new()),
            client_id: RwLock::new(vec![]),
            crypter,
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
        Self::new(crate::crypt::ChaCha20Crypt::default())
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
        let id = sp.scan_id.clone().unwrap_or_default();
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
    async fn append_fetched_result(
        &self,
        id: &str,
        (status, results): FetchResult,
    ) -> Result<(), Error> {
        let mut scans = self.scans.write().await;
        let progress = scans.get_mut(id).ok_or(Error::NotFound)?;
        progress.status = status;
        let mut len = progress.results.len();
        for mut result in results {
            result.id = len;
            len += 1;
            let bytes = serde_json::to_vec(&result)?;
            progress.results.push(self.crypter.encrypt(bytes).await);
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
            if let Some(id) = progress.scan.scan_id.as_ref() {
                result.push(id.clone());
            }
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

#[async_trait]
impl<E> OIDStorer for Storage<E>
where
    E: Send + Sync + 'static,
{
    async fn push_oids(&self, hash: String, mut oids: Vec<String>) -> Result<(), Error> {
        let mut o = self.oids.write().await;
        o.clear();
        o.append(&mut oids);
        o.shrink_to_fit();
        let mut f = self.hash.write().await;
        *f = hash;
        Ok(())
    }

    async fn oids(&self) -> Result<Box<dyn Iterator<Item = String> + Send>, Error> {
        let o = self.oids.read().await.clone();
        Ok(Box::new(o.into_iter()))
    }

    async fn feed_hash(&self) -> String {
        self.hash.read().await.clone()
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
        let id = scan.scan_id.clone().unwrap_or_default();
        storage.insert_scan(scan).await.unwrap();
        let (retrieved, _) = storage.get_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id.unwrap_or_default(), id);
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
            },
            ..Default::default()
        };

        scan.target.credentials = vec![pw];

        let id = scan.scan_id.clone().unwrap_or_default();
        storage.insert_scan(scan).await.unwrap();
        let (retrieved, _) = storage.get_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id.unwrap_or_default(), id);
        assert_ne!(retrieved.target.credentials[0].password(), "test");

        let (retrieved, _) = storage.get_decrypted_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id.unwrap_or_default(), id);
        assert_eq!(retrieved.target.credentials[0].password(), "test");
    }

    async fn store_scan(storage: &Storage<crypt::ChaCha20Crypt>) -> String {
        let mut scan = Scan::default();
        let id = uuid::Uuid::new_v4().to_string();
        scan.scan_id = Some(id.clone());
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
        let id = scan.scan_id.clone().unwrap_or_default();
        storage.insert_scan(scan).await.unwrap();
        let fetch_result = (models::Status::default(), vec![models::Result::default()]);
        storage
            .append_fetched_result(&id, fetch_result)
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
