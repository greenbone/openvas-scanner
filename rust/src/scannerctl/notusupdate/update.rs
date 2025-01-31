// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::Path;
use std::path::PathBuf;

use crate::Filename;
use crate::{CliError, CliErrorKind};

use scannerlib::feed;
use scannerlib::models;
use scannerlib::nasl::syntax::{FSPluginLoader, LoadError};
use scannerlib::nasl::WithErrorInfo;
use scannerlib::notus::{AdvisoryLoader, HashsumAdvisoryLoader};
use scannerlib::storage::{ContextKey, Dispatcher, Field};

pub fn signature_error(e: impl std::fmt::Display) -> CliError {
    CliErrorKind::LoadError(LoadError::Dirty(e.to_string()))
        .with(Filename(Path::new(feed::Hasher::Sha256.sum_file())))
}

pub fn run<S>(storage: S, path: PathBuf, signature_check: bool) -> Result<(), CliError>
where
    S: Sync + Send + Dispatcher,
{
    let loader = FSPluginLoader::new(path);
    let advisories_files = match HashsumAdvisoryLoader::new(loader.clone()) {
        Ok(loader) => loader,
        Err(_) => {
            return Err(CliErrorKind::LoadError(LoadError::Dirty(
                "Problem loading advisory".to_string(),
            ))
            .into())
        }
    };

    if signature_check {
        match advisories_files.verify_signature() {
            Ok(_) => tracing::info!("Signature check succsessful"),
            Err(feed::VerifyError::MissingKeyring) => {
                tracing::warn!("Signature check enabled but missing keyring");
                return Err(feed::VerifyError::MissingKeyring.into());
            }
            Err(feed::VerifyError::BadSignature(e)) => {
                tracing::warn!("{}", e);
                return Err(signature_error(e));
            }
            Err(e) => {
                tracing::warn!("Unexpected error during signature verification: {e}");
                return Err(signature_error(e));
            }
        }
    }

    // Get the all products files and process
    for filename in advisories_files.get_advisories().unwrap().iter() {
        let advisories = advisories_files.load_advisory(filename).unwrap();

        for adv in advisories.advisories {
            let _ = storage.dispatch(
                &ContextKey::FileName(filename.to_owned()),
                Field::NotusAdvisory(Box::new(Some(models::VulnerabilityData {
                    adv,
                    family: advisories.family.clone(),
                    filename: filename.to_owned(),
                }))),
            );
        }
    }
    let _ = storage.dispatch(
        &ContextKey::FileName("notuscache".to_string()),
        Field::NotusAdvisory(Box::new(None)),
    );

    Ok(())
}
