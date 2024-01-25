// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::path::PathBuf;

use crate::{CliError, CliErrorKind};
use models::{Vulnerability, VulnerabilityData};
use nasl_syntax::{FSPluginLoader, LoadError};
use notus::loader::{hashsum::HashsumAdvisoryLoader, AdvisoryLoader};
use redis_storage::NOTUS_KEY;
use storage::{Dispatcher, Field::NOTUS, Notus};

pub fn run<S>(storage: S, path: PathBuf, signature_check: bool) -> Result<(), CliError>
where
    S: Sync + Send + Dispatcher<String>,
{
    let loader = FSPluginLoader::new(path.to_string_lossy().to_string());
    let advisories_files = match HashsumAdvisoryLoader::new(loader.clone()) {
        Ok(loader) => loader,
        Err(_) => {
            return Err(CliError {
                filename: "".to_string(),
                kind: CliErrorKind::LoadError(LoadError::Dirty(
                    "Problem loading advisory".to_string(),
                )),
            })
        }
    };

    // Perform signature check if enabled.
    if signature_check {
        match advisories_files.verify_signature() {
            Ok(_) => tracing::info!("Signature check succsessful"),
            Err(feed::VerifyError::MissingKeyring) => {
                tracing::warn!("Signature check enabled but missing keyring");
                return Err(feed::VerifyError::MissingKeyring.into());
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
                    kind: crate::CliErrorKind::LoadError(nasl_syntax::LoadError::Dirty(
                        e.to_string(),
                    )),
                });
            }
        }
    } else {
        tracing::warn!("Signature check disabled");
    }

    // Get the all products files and process
    for filename in advisories_files.get_advisories().unwrap().iter() {
        let advisories = advisories_files.load_advisory(filename).unwrap();

        // Each products contains multiple advisories. Each advisory is converted
        // to a Vulnerability, serialized, and stored as a single entry in the cache.
        for adv in advisories.iter() {
            let key = format!("internal/notus/advisories/{}", adv.oid);
            let value = Vulnerability::from(&VulnerabilityData {
                adv,
                product_data: &advisories,
                filename,
            });

            let serialized = serde_json::to_string(&value).unwrap();

            let _ = storage.dispatch(
                &key,
                NOTUS(Notus {
                    value: serialized.into(),
                }),
            );
        }
        // Finally, set the "notuscache" key, so the cache can be found under this key.
        let _ = storage.dispatch(&NOTUS_KEY.to_string(), NOTUS(Notus { value: 1.into() }));
    }

    Ok(())
}
