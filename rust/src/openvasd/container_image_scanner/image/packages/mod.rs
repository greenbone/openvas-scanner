use crate::container_image_scanner::image::extractor::FileSystemLocator;

use super::extractor::LocatorError;

mod debian;
mod rpm;

type PackageError = LocatorError;

pub fn package_files() -> impl Iterator<Item = &'static &'static str> {
    debian::DPKGStatusFile::wanted_files()
        .iter()
        .chain(<rpm::RPMDBSqliteFile>::wanted_files())
}

/// ResolvePackages resolves packages to a Notus compatible string
///
///
/// Onlike the traits used by scheduling there are just async without Pin Box and lifetime. This
/// should make it easier for the implementation as the lifetime handling is done within ToNotus.
///
/// When the implementation is not meant for the image it must return NotFound so that AllTypes is
/// aware of that and don't return an empty list and prints a warning but just tries the next
/// implementation.
trait ResolvePackages {
    async fn packages(locator: &FileSystemLocator) -> Result<Vec<String>, PackageError>;
}

pub struct AllTypes;

impl AllTypes {
    pub async fn packages(locator: &FileSystemLocator) -> Vec<String> {
        let result = <debian::DPKGStatusFile>::packages(locator).await;
        match result {
            Ok(packages) => return packages,
            Err(PackageError::NotFound(_)) => {}
            Err(e) => {
                tracing::warn!(error = %e,"Unable to parse packages with {}",stringify!(debian::DPKGStatusFile));
                return vec![];
            }
        }
        let result = <rpm::RPMDBSqliteFile>::packages(locator).await;
        match result {
            Ok(packages) => return packages,
            Err(PackageError::NotFound(_)) => {}
            Err(e) => {
                tracing::warn!(error = %e,"Unable to parse packages with {}",stringify!(rpm::RPMDBSqliteFile));
                return vec![];
            }
        }
        tracing::debug!(
            "No packages found, might be because the package DB got deleted or unsupported OS."
        );
        vec![]
    }
}

#[cfg(test)]
mod test_utils {
    use std::path::PathBuf;

    use crate::container_image_scanner::image::extractor::FileSystemLocator;

    pub fn locator_with_files(files: &[(&str, &str)]) -> FileSystemLocator {
        let temp_dir = tempfile::tempdir().unwrap();

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for (image_path, fixture_path) in files {
            let destination = temp_dir.path().join(image_path);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(manifest_dir.join(fixture_path), destination).unwrap();
        }

        // We keep the temp_dir alive because the `Drop` impl of
        // `FileSystemLocator` cleans it up
        FileSystemLocator::for_test(temp_dir.keep(), "amd64")
    }
}

#[cfg(test)]
mod tests {
    use crate::container_image_scanner::image::packages::test_utils::locator_with_files;

    #[tokio::test]
    async fn find_packages() {
        let locator = locator_with_files(&[(
            "var/lib/dpkg/status",
            "data/tests/images/victim/var/lib/dpkg/status",
        )]);
        let packages = super::AllTypes::packages(&locator).await;
        assert_eq!(packages.len(), 629);
    }
}
