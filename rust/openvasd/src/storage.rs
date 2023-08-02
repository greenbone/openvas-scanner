use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{crypt, scan::FetchResult};

#[derive(Debug)]
pub enum Error {
    SerializationError,
    NotFound,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            NotFound => write!(f, "not found"),
            SerializationError => write!(f, "serialization error"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::SerializationError
    }
}

impl From<crypt::ParseError> for Error {
    fn from(_: crypt::ParseError) -> Self {
        Self::SerializationError
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Self::SerializationError
    }
}

#[async_trait]
/// A trait for getting the progress of a scan, the scan itself with decrypted credentials and
/// encrypted as well as results.
///
/// The main usage of this trait is in the controller and when transforming a scan to a osp
pub trait ProgressGetter {
    /// Returns the scan.
    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error>;
    /// Returns the scan with dcecrypted passwords.
    ///
    /// This method should only be used when the password is required. E.g.
    /// when transforming a scan to a osp command.
    async fn get_decrypted_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error>;
    /// Returns all scans.
    async fn get_scans(&self) -> Result<Vec<(models::Scan, models::Status)>, Error>;
    /// Returns the status of a scan.
    async fn get_status(&self, id: &str) -> Result<models::Status, Error>;
    /// Returns the results of a scan as json bytes.
    ///
    /// OpenVASD just stores to results without processing them therefore we
    /// can just return the json bytes.
    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Vec<Vec<u8>>, Error>;
}

#[async_trait]
/// A trait for storing scans.
///
/// The main usage of this trait is in the controller and when a user inserts or removes a scan.
pub trait ScanStorer {
    /// Inserts a scan.
    async fn insert_scan(&self, t: models::Scan) -> Result<Option<models::Scan>, Error>;
    /// Removes a scan.
    async fn remove_scan(&self, id: &str) -> Result<Option<(models::Scan, models::Status)>, Error>;
    /// Updates a status of a scan.
    ///
    /// This is required when a scan is started or stopped.
    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error>;
}

#[async_trait]
/// A trait for appending results from a different source.
///
/// This is used when a scan is started and the results are fetched from ospd.
pub trait AppendFetchResult {
    async fn append_fetch_result(&self, id: &str, results: FetchResult) -> Result<(), Error>;
}

#[async_trait]
/// Combines the traits `ProgressGetter`, `ScanStorer` and `AppendFetchResult`.
pub trait Storage: ProgressGetter + ScanStorer + AppendFetchResult {}

#[async_trait]
impl<T> Storage for T where T: ProgressGetter + ScanStorer + AppendFetchResult {}

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
pub struct InMemoryStorage<E> {
    scans: RwLock<HashMap<String, Progress>>,
    crypter: E,
}

impl<E> InMemoryStorage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    pub fn new(crypter: E) -> Self {
        Self {
            scans: RwLock::new(HashMap::new()),
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

impl Default for InMemoryStorage<crate::crypt::ChaCha20Crypt> {
    fn default() -> Self {
        Self::new(crate::crypt::ChaCha20Crypt::default())
    }
}

#[async_trait]
impl<E> ScanStorer for InMemoryStorage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn insert_scan(&self, sp: models::Scan) -> Result<Option<models::Scan>, Error> {
        let id = sp.scan_id.clone().unwrap_or_default();
        let mut scans = self.scans.write().await;
        if let Some(prgs) = scans.get_mut(&id) {
            let old = prgs.scan.clone();
            prgs.scan = sp;
            Ok(Some(old))
        } else {
            let progress = self.new_progress(sp).await?;
            let old = scans.insert(id.clone(), progress);
            Ok(old.map(|p| p.scan))
        }
    }

    async fn remove_scan(&self, id: &str) -> Result<Option<(models::Scan, models::Status)>, Error> {
        let mut scans = self.scans.write().await;
        Ok(scans.remove(id).map(|p| (p.scan, p.status)))
    }

    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error> {
        let mut scans = self.scans.write().await;
        let progress = scans.get_mut(id).ok_or(Error::NotFound)?;
        progress.status = status;
        Ok(())
    }
}

#[async_trait]
impl<E> AppendFetchResult for InMemoryStorage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn append_fetch_result(
        &self,
        id: &str,
        (status, results): FetchResult,
    ) -> Result<(), Error> {
        let mut scans = self.scans.write().await;
        let progress = scans.get_mut(id).ok_or(Error::NotFound)?;
        progress.status = status;
        for result in &results {
            let bytes = serde_json::to_vec(result)?;
            progress.results.push(self.crypter.encrypt_sync(bytes));
        }
        Ok(())
    }
}

#[async_trait]
impl<E> ProgressGetter for InMemoryStorage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn get_scans(&self) -> Result<Vec<(models::Scan, models::Status)>, Error> {
        let scans = self.scans.read().await;
        let mut result = Vec::with_capacity(scans.len());
        for (_, progress) in scans.iter() {
            result.push((progress.scan.clone(), progress.status.clone()));
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
    ) -> Result<Vec<Vec<u8>>, Error> {
        let scans = self.scans.read().await;
        let progress = scans.get(id).ok_or(Error::NotFound)?;
        let from = from.unwrap_or(0);
        let to = to.unwrap_or(progress.results.len());
        let to = to.min(progress.results.len());
        if from > to || from > progress.results.len() {
            return Ok(Vec::new());
        }
        let mut results = Vec::with_capacity(to - from);
        for result in &progress.results[from..to] {
            results.push(self.crypter.decrypt_sync(result));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use models::Scan;

    use super::*;

    #[tokio::test]
    async fn store_delete_scan() {
        let storage = InMemoryStorage::default();
        let scan = Scan::default();
        let id = scan.scan_id.clone().unwrap_or_default();
        let inserted = storage.insert_scan(scan).await.unwrap();
        assert!(inserted.is_none());
        let (retrieved, _) = storage.get_scan(&id).await.unwrap();
        assert_eq!(retrieved.scan_id.unwrap_or_default(), id);
        let (removed, _) = storage.remove_scan(&id).await.unwrap().unwrap();
        assert_eq!(removed.scan_id.unwrap_or_default(), id);
    }

    #[tokio::test]
    async fn encrypt_decrypt_passwords() {
        let storage = InMemoryStorage::default();
        let mut scan = Scan::default();
        let mut pw = models::Credential::default();
        pw.credential_type = models::CredentialType::UP {
            username: "test".to_string(),
            password: "test".to_string(),
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

    async fn store_scan(storage: &InMemoryStorage<crypt::ChaCha20Crypt>) -> String {
        let mut scan = Scan::default();
        let id = uuid::Uuid::new_v4().to_string();
        scan.scan_id = Some(id.clone());
        let inserted = storage.insert_scan(scan).await.unwrap();
        assert!(inserted.is_none());
        id
    }

    #[tokio::test]
    async fn get_scans() {
        let storage = InMemoryStorage::default();
        for _ in 0..10 {
            store_scan(&storage).await;
        }
        let scans = storage.get_scans().await.unwrap();
        assert_eq!(scans.len(), 10);
    }

    #[tokio::test]
    async fn append_results() {
        let storage = InMemoryStorage::default();
        let scan = Scan::default();
        let id = scan.scan_id.clone().unwrap_or_default();
        let inserted = storage.insert_scan(scan).await.unwrap();
        assert!(inserted.is_none());
        let fetch_result = (models::Status::default(), vec![models::Result::default()]);
        storage
            .append_fetch_result(&id, fetch_result)
            .await
            .unwrap();
        let results = storage.get_results(&id, None, None).await.unwrap();
        assert_eq!(results.len(), 1);
        let result: models::Result = serde_json::from_slice(&results[0]).unwrap();
        assert_eq!(result, models::Result::default());
        let results = storage.get_results(&id, Some(23), Some(1)).await.unwrap();
        assert_eq!(results.len(), 0);
        let results = storage.get_results(&id, Some(0), Some(0)).await.unwrap();
        assert_eq!(results.len(), 0);
        let results = storage.get_results(&id, Some(0), Some(5)).await.unwrap();
        assert_eq!(results.len(), 1);
        let results = storage.get_results(&id, Some(0), None).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn update_status() {
        let storage = InMemoryStorage::default();
        let id = store_scan(&storage).await;
        let (_, mut status) = storage.get_scan(&id).await.unwrap();
        assert_eq!(status.status, models::Phase::Stored);
        status.status = models::Phase::Requested;
        storage.update_status(&id, status).await.unwrap();
        let (_, status) = storage.get_scan(&id).await.unwrap();
        assert_eq!(status.status, models::Phase::Requested);
    }
}
