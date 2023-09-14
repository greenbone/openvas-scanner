// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::path::PathBuf;

use nasl_interpreter::FSPluginLoader;
use storage::Dispatcher;

use crate::CliError;

pub fn run<S>(storage: S, path: PathBuf) -> Result<(), CliError>
where
    S: Sync + Send + Dispatcher<String>,
{
    tracing::debug!("description run syntax in {path:?}.");
    // needed to strip the root path so that we can build a relative path
    // e.g. 2006/something.nasl
    let loader = FSPluginLoader::new(path);
    let verifier = feed::HashSumNameLoader::sha256(&loader)?;
    let updater = feed::Update::init("1", 5, loader.clone(), storage, verifier);

    match updater.verify_signature() {
        Ok(_) => tracing::info!("Signature check succsessful"),
        Err(feed::VerifyError::SignatureCheckDisabled) => {
            tracing::warn!("Signature check disabled")
        }
        Err(feed::VerifyError::BadSignature(e)) => {
            tracing::warn!("{}", e);
            return Err(CliError {
                filename: feed::Hasher::Sha256.sum_file().to_string(),
                kind: crate::CliErrorKind::LoadError(nasl_syntax::LoadError::Dirty(e)),
            });
        }
        Err(e) => {
            tracing::warn!("Unexpected error during signature verification: {e}");
            return Err(CliError {
                filename: feed::Hasher::Sha256.sum_file().to_string(),
                kind: crate::CliErrorKind::LoadError(nasl_syntax::LoadError::Dirty(e.to_string())),
            });
        }
    }

    for s in updater {
        let s = s?;
        tracing::trace!("updated {s}");
    }

    Ok(())
}
