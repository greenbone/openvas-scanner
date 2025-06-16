// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::Path;

use scannerlib::feed::FakeVerifier;
use scannerlib::nasl::utils::scan_ctx::ContextStorage;
use scannerlib::{feed, nasl::FSPluginLoader};

use crate::CliError;
use crate::notus_update::update::signature_error;

pub async fn run<S>(storage: S, path: &Path, signature_check: bool) -> Result<(), CliError>
where
    S: ContextStorage,
{
    tracing::debug!("description run syntax in {path:?}.");
    // needed to strip the root path so that we can build a relative path
    // e.g. 2006/something.nasl
    let loader = FSPluginLoader::new(path);
    let verifier = feed::HashSumNameLoader::sha256(&loader)?;
    let updater = feed::Update::init("1", 5, &loader, &storage, verifier);

    if signature_check {
        match updater.verify_signature() {
            Ok(_) => tracing::info!("Signature check successful"),
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

pub async fn run_no_verifier<S>(storage: S, path: &Path) -> Result<(), CliError>
where
    S: ContextStorage,
{
    tracing::debug!("description run syntax in {path:?}.");
    // needed to strip the root path so that we can build a relative path
    // e.g. 2006/something.nasl
    let loader = FSPluginLoader::new(path);
    let verifier = FakeVerifier::new(&loader);
    let updater = feed::Update::init("1", 5, &loader, &storage, verifier);

    updater.perform_update().await?;

    Ok(())
}
