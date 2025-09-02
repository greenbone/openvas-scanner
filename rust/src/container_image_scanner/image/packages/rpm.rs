use std::{io, path::PathBuf};

use super::{PackageError, ResolvePackages};
use crate::container_image_scanner::image::extractor::{Locator, LocatorError};

pub struct RPMDBSqliteFile;

impl RPMDBSqliteFile {
    /// As it is used by the extractor, and we don't know the target path at compile time it needs
    /// to be relatively.
    pub(super) const fn wanted_files() -> &'static [&'static str] {
        &[
            "var/lib/rpm/rpmdb.sqlite",
            "usr/lib/sysimage/rpm/rpmdb.sqlite",
            "var/lib/rpm/Packages",
            "usr/lib/sysimage/rpm/Packages",
            "var/lib/rpm/Packages.db",
            "usr/lib/sysimage/rpm/Packages.db",
        ]
    }
}

impl RPMDBSqliteFile {
    async fn read_rpmdb(path: PathBuf) -> Result<Vec<String>, super::PackageError> {
        let packages = tokio::task::spawn_blocking(move || {
            rpmdb::read_packages(path).map_err(|e| {
                super::PackageError::ReadError(io::Error::other(format!("rpmdb error: {e}")))
            })
        })
        .await
        .map_err(|e| {
            // unreachable, however I think that is easier to read then a match statement
            super::PackageError::ReadError(io::Error::other(format!(
                "rpmdb::read_packages must not panic: {e}"
            )))
        })??;

        tracing::debug!(packages = packages.len(), "Packages found.");
        Ok(packages
            .iter()
            .map(|package| {
                format!(
                    "{}-{}-{}.{}",
                    package.name, package.version, package.release, package.arch
                )
            })
            .collect())
    }
}

impl ResolvePackages for RPMDBSqliteFile {
    async fn packages<T>(locator: &T) -> Result<Vec<String>, super::PackageError>
    where
        T: Locator,
    {
        let mut result = Vec::new();

        for path in Self::wanted_files() {
            match locator.locate(path).await {
                Ok(rpmdb_path) => result.extend(Self::read_rpmdb(rpmdb_path.into_inner()).await?),
                Err(LocatorError::NotFound(x)) => {
                    tracing::trace!(path = x, "Skipping because not found")
                }
                Err(LocatorError::ReadError(e)) => {
                    tracing::warn!(error=%e, "Unable to read file. Aborting.");
                    return Err(e.into());
                }
            }
        }

        if result.is_empty() {
            Err(PackageError::NotFound("".into()))
        } else {
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::container_image_scanner::image::packages::{
        ResolvePackages, fakes::FakeLocator, rpm::RPMDBSqliteFile,
    };

    #[tokio::test]
    async fn find_packages() {
        let packages = RPMDBSqliteFile::packages(&FakeLocator {}).await.unwrap();
        assert!(!packages.is_empty(), "expected some packages");
    }
}
