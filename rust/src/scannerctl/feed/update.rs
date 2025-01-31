// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::Path;

use scannerlib::storage::Dispatcher;
use scannerlib::{
    feed,
    nasl::{syntax::LoadError, FSPluginLoader},
};

use crate::notusupdate::update::signature_error;
use crate::{CliError, CliErrorKind};

pub async fn run<S>(storage: S, path: &Path, signature_check: bool) -> Result<(), CliError>
where
    S: Sync + Send + Dispatcher,
{
    tracing::debug!("description run syntax in {path:?}.");
    // needed to strip the root path so that we can build a relative path
    // e.g. 2006/something.nasl
    let loader = FSPluginLoader::new(path);
    let verifier = feed::HashSumNameLoader::sha256(&loader)?;
    let updater = feed::Update::init("1", 5, &loader, &storage, verifier);

    if signature_check {
        match updater.verify_signature() {
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

    updater.perform_update().await?;

    Ok(())
}
