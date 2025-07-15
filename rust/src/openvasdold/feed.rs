// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    path::Path,
    sync::{Arc, RwLock},
};

use scannerlib::{
    feed::{self, HashSumNameLoader},
    nasl::{FSPluginLoader, utils::scan_ctx::ContextStorage},
    scheduling::SchedulerStorage,
    storage::{
        Dispatcher, Remover, Retriever, ScanID,
        error::StorageError,
        items::{
            kb::{GetKbContextKey, KbContextKey, KbItem},
            nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
            result::{ResultContextKeySingle, ResultItem},
        },
    },
};

#[derive(Debug, Default, Clone)]
pub struct FeedIdentifier {
    oids: Arc<RwLock<Vec<String>>>,
}

impl FeedIdentifier {
    /// Get the oids from a feed
    pub async fn from_feed<S>(
        path: S,
        signature_check: bool,
    ) -> Result<Vec<String>, feed::UpdateError>
    where
        S: AsRef<Path> + Clone + std::fmt::Debug + Sync + Send,
    {
        let oids = Arc::new(RwLock::new(Vec::new()));
        let storage = FeedIdentifier {
            oids: Arc::clone(&oids),
        };
        tracing::debug!("getting oids from ${path:?}");
        // needed to strip the root path so that we can build a relative path
        // e.g. 2006/something.nasl
        let loader = FSPluginLoader::new(path);
        let verifier = HashSumNameLoader::sha256(&loader)?;
        // TODO: Change the version to be a parameter
        let updater = feed::Update::init("1", 5, &loader, &storage, verifier);

        if signature_check {
            match updater.verify_signature() {
                Ok(_) => tracing::info!("Signature check succsessful"),
                Err(feed::VerifyError::MissingKeyring) => {
                    tracing::warn!("Signature check enabled but missing keyring")
                }
                Err(feed::VerifyError::BadSignature(e)) => {
                    tracing::warn!("{}", e);
                    return Err(feed::UpdateError {
                        key: feed::Hasher::Sha256.sum_file().to_string(),
                        kind: feed::UpdateErrorKind::VerifyError(feed::VerifyError::BadSignature(
                            e.to_string(),
                        )),
                    });
                }
                Err(e) => {
                    tracing::warn!("Unexpected error during signature verification: {e}");
                    return Err(feed::UpdateError {
                        key: feed::Hasher::Sha256.sum_file().to_string(),
                        kind: feed::UpdateErrorKind::VerifyError(feed::VerifyError::BadSignature(
                            e.to_string(),
                        )),
                    });
                }
            }
        } else {
            tracing::warn!("Signature check disabled");
        }

        updater.perform_update().await?;

        let oids = oids.read().map_err(|e| feed::UpdateError {
            kind: feed::UpdateErrorKind::StorageError(StorageError::from(e)),
            key: "feed_oid poisoned".to_string(),
        })?;

        let oids = oids.clone();
        Ok(oids)
    }

    pub fn sumfile_hash<S>(path: S) -> Result<String, feed::UpdateError>
    where
        S: AsRef<Path> + Clone + std::fmt::Debug + Sync + Send,
    {
        let loader = FSPluginLoader::new(path);
        let verifier = HashSumNameLoader::sha256(&loader)?;
        verifier.sumfile_hash().map_err(|e| feed::UpdateError {
            kind: feed::UpdateErrorKind::VerifyError(e),
            key: "feed_oid poisoned".to_string(),
        })
    }
}

impl Dispatcher<FileName> for FeedIdentifier {
    type Item = Nvt;
    fn dispatch(&self, _: FileName, item: Nvt) -> Result<(), StorageError> {
        let mut oids = self.oids.write()?;
        oids.push(item.oid);
        Ok(())
    }
}

impl Dispatcher<KbContextKey> for FeedIdentifier {
    type Item = KbItem;
    fn dispatch(&self, _: KbContextKey, _: Self::Item) -> Result<(), StorageError> {
        Ok(())
    }
}

impl Dispatcher<ScanID> for FeedIdentifier {
    type Item = ResultItem;
    fn dispatch(&self, _: ScanID, _: Self::Item) -> Result<(), StorageError> {
        Ok(())
    }
}

impl Dispatcher<FeedVersion> for FeedIdentifier {
    type Item = String;
    fn dispatch(&self, _: FeedVersion, _: Self::Item) -> Result<(), StorageError> {
        Ok(())
    }
}

impl Retriever<KbContextKey> for FeedIdentifier {
    type Item = Vec<KbItem>;
    fn retrieve(&self, _: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Retriever<GetKbContextKey> for FeedIdentifier {
    type Item = Vec<(String, Vec<KbItem>)>;
    fn retrieve(&self, _: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Retriever<ResultContextKeySingle> for FeedIdentifier {
    type Item = ResultItem;
    fn retrieve(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Retriever<ScanID> for FeedIdentifier {
    type Item = Vec<ResultItem>;
    fn retrieve(&self, _: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Retriever<FeedVersion> for FeedIdentifier {
    type Item = String;
    fn retrieve(&self, _: &FeedVersion) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Retriever<Feed> for FeedIdentifier {
    type Item = Vec<Nvt>;
    fn retrieve(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Retriever<Oid> for FeedIdentifier {
    type Item = Nvt;
    fn retrieve(&self, _: &Oid) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Retriever<FileName> for FeedIdentifier {
    type Item = Nvt;
    fn retrieve(&self, _: &FileName) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Remover<KbContextKey> for FeedIdentifier {
    type Item = Vec<KbItem>;
    fn remove(&self, _: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Remover<ResultContextKeySingle> for FeedIdentifier {
    type Item = ResultItem;
    fn remove(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl Remover<ScanID> for FeedIdentifier {
    type Item = Vec<ResultItem>;
    fn remove(&self, _: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        Ok(None)
    }
}

impl SchedulerStorage for FeedIdentifier {}
impl ContextStorage for FeedIdentifier {}
