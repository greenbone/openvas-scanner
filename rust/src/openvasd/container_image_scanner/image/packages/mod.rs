use super::extractor::{Locator, LocatorError};
use crate::concat_slices;

mod debian;
mod rpm;

type PackageError = LocatorError;

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
    async fn packages<T>(locator: &T) -> Result<Vec<String>, PackageError>
    where
        T: Locator;
}

/// This is required for the extractor
///
/// The extractor will use the relatives paths of those packages to determine if we need to extract
/// that file or if we can discard it to avoid using unnecessarily large amounts of disk space.
pub const PACKAGE_FILES: &[&str] = concat_slices!(&[
    <debian::DPKGStatusFile>::wanted_files(),
    <rpm::RPMDBSqliteFile>::wanted_files(),
]);
pub struct AllTypes;

impl AllTypes {
    pub async fn packages<T>(locator: &T) -> Vec<String>
    where
        T: Locator + Sync + Send,
    {
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
mod fakes {
    use crate::container_image_scanner::{
        PromiseRef,
        image::extractor::{Location, Locator, LocatorError},
    };

    pub struct FakeLocator;

    impl Locator for FakeLocator {
        fn locate(&self, name: &str) -> PromiseRef<'_, Result<Location, LocatorError>> {
            let name = name.to_owned();

            Box::pin(async move {
                let file = match &name as &str {
                    "var/lib/dpkg/status" => "data/tests/images/victim/var/lib/dpkg/status",
                    "var/lib/rpm/rpmdb.sqlite" => "crates/rpmdb-rs/testdata/rpmdb.sqlite",
                    _ => {
                        return Err(LocatorError::NotFound(
                            "No such file or directory".to_owned(),
                        ));
                    }
                };
                let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(file);
                Ok(path.into())
            })
        }

        fn architecture(&self) -> &str {
            "amd64"
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::container_image_scanner::image::packages::fakes::FakeLocator;

    #[tokio::test]
    async fn find_packages() {
        let packages = super::AllTypes::packages(&FakeLocator {}).await;
        assert_eq!(packages.len(), 629);
    }
}
