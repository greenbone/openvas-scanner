// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    path::Path,
    sync::{Arc, RwLock},
};

use scannerlib::storage::{ContextKey, StorageError};
use scannerlib::{
    feed::{self, HashSumNameLoader},
    nasl::FSPluginLoader,
    storage::{item::NVTField, Dispatcher, Field},
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

impl Dispatcher for FeedIdentifier {
    fn dispatch(&self, _: &ContextKey, scope: Field) -> Result<(), StorageError> {
        if let Field::NVT(NVTField::Oid(x)) = scope {
            let mut oids = self.oids.write()?;
            oids.push(x);
        }
        Ok(())
    }

    fn dispatch_replace(&self, _: &ContextKey, _scope: Field) -> Result<(), StorageError> {
        Ok(())
    }

    fn on_exit(&self, _: &ContextKey) -> Result<(), StorageError> {
        Ok(())
    }
}
