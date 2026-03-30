// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::Path;
use std::path::PathBuf;

use crate::Filename;
use crate::{CliError, CliErrorKind};

use scannerlib::feed;
use scannerlib::nasl::WithErrorInfo;
use scannerlib::nasl::syntax::LoadError;
use scannerlib::nasl::syntax::Loader;
use scannerlib::notus::advisories::VulnerabilityData;
use scannerlib::notus::advisory_loader;
use scannerlib::storage::Dispatcher;
use scannerlib::storage::items::notus_advisory::NotusCache;
use scannerlib::storage::redis::RedisAddAdvisory;
use scannerlib::storage::redis::RedisAddNvt;
use scannerlib::storage::redis::RedisGetNvt;
use scannerlib::storage::redis::RedisStorage;
use scannerlib::storage::redis::RedisWrapper;

pub(crate) trait NotusStorage:
    Dispatcher<(), Item = VulnerabilityData> + Dispatcher<NotusCache, Item = ()>
{
}

impl<S> NotusStorage for RedisStorage<S> where
    S: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Send
{
}

pub fn signature_error(e: impl std::fmt::Display) -> CliError {
    CliErrorKind::LoadError(LoadError::Dirty(e.to_string()))
        .with(Filename(Path::new(feed::Hasher::Sha256.sum_file())))
}

pub async fn run<S>(storage: S, path: PathBuf, signature_check: bool) -> Result<(), CliError>
where
    S: NotusStorage,
{
    let loader = Loader::from_feed_path(path);
    // TODO: change if signature_check than use HashsumAdvisoryLoader and verify it otherwise use
    // FileSystemLoader
    //
    let advisories_files = match advisory_loader(signature_check, &loader) {
        Ok(loader) => loader,
        Err(_) => {
            return Err(CliErrorKind::LoadError(LoadError::Dirty(
                "Problem loading advisory".to_string(),
            ))
            .into());
        }
    };

    // Get the all products files and process
    for entry in advisories_files {
        let container = entry?;

        for adv in container.advisories.advisories {
            let _ = storage
                .dispatch(
                    (),
                    VulnerabilityData {
                        adv,
                        family: container.advisories.family.clone(),
                        filename: container.filename.clone(),
                    },
                )
                .await;
        }
    }
    let _ = storage.dispatch(NotusCache, ()).await;

    Ok(())
}
