// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    path::Path,
    sync::{Arc, RwLock},
};

use storage::StorageError::{self};
#[derive(Debug, Default, Clone)]
pub struct FeedIdentifier {
    oids: Arc<RwLock<Vec<String>>>,
}

impl FeedIdentifier {
    /// Get the oids from a feed
    pub fn from_feed<S>(path: S) -> Result<Vec<String>, feed::UpdateError>
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
        let loader = nasl_interpreter::FSPluginLoader::new(path);
        let verifier = feed::HashSumNameLoader::sha256(&loader)?;
        let updater = feed::Update::init("1", 5, loader.clone(), storage, verifier);

        for s in updater {
            s?;
        }

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
        let loader = nasl_interpreter::FSPluginLoader::new(path);
        let verifier = feed::HashSumNameLoader::sha256(&loader)?;
        verifier.sumfile_hash().map_err(|e| feed::UpdateError {
            kind: feed::UpdateErrorKind::VerifyError(e),
            key: "feed_oid poisoned".to_string(),
        })
    }
}

impl storage::Dispatcher<String> for FeedIdentifier {
    fn dispatch(&self, _: &String, scope: storage::Field) -> Result<(), storage::StorageError> {
        use storage::nvt::NVTField::Oid;
        if let storage::Field::NVT(Oid(x)) = scope {
            let mut oids = self.oids.write()?;
            oids.push(x);
        }
        Ok(())
    }

    fn on_exit(&self) -> Result<(), storage::StorageError> {
        Ok(())
    }
}
