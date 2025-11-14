use std::pin::Pin;

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

/// This transforms downloaded layer to Notus compatible packages
pub trait ToNotus {
    fn packages<'a, T>(locator: &'a T) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>>
    where
        T: Locator + Sync + Send;
}

macro_rules! generate_all_types {
    ( $($backend:ty),+ $(,)? ) => {

        /// This is required for the extractor
        ///
        /// The extractor will use the relatives paths of those packages to determine if we need to
        /// extract that file or if we can discard it. This filtering method is required for
        /// to not use too much disk space when running.
        pub const PACKAGE_FILES: &[&str] = concat_slices!(&[
                    $(
                    <$backend>::wanted_files(),
                    )+
        ]);


        pub struct AllTypes;

        impl ToNotus for AllTypes {
            fn packages<'a, T>(locator: &'a T) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>>
            where
                T: Locator + Sync + Send,
            {
                Box::pin(async move {
                    $(
                        let result = <$backend>::packages(locator).await;
                        match result {
                            Ok(packages) => return packages,
                            Err(PackageError::NotFound(_)) => {},
                            Err(e) => {
                                tracing::warn!(error=%e, "Unable to parse packages with {}", stringify!($backend));
                                return vec![];
                            }
                        }
                    )+

                    tracing::debug!("No packages found, might be because the package DB got deleted or unsupported OS.");
                    vec![]
                })
            }
        }
    };
}

generate_all_types! {debian::DPKGStatusFile, rpm::RPMDBSqliteFile }

#[cfg(test)]
mod fakes {
    use crate::container_image_scanner::{
        PinBoxFutRef,
        image::extractor::{Location, Locator, LocatorError},
    };

    pub struct FakeLocator;

    impl Locator for FakeLocator {
        fn locate(&self, name: &str) -> PinBoxFutRef<'_, Result<Location, LocatorError>> {
            let name = name.to_owned();

            Box::pin(async move {
                let file = match &name as &str {
                    "var/lib/dpkg/status" => "test-data/images/victim/var/lib/dpkg/status",
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
    use crate::container_image_scanner::image::packages::{ToNotus, fakes::FakeLocator};

    #[tokio::test]
    async fn find_packages() {
        let packages = super::AllTypes::packages(&FakeLocator {}).await;
        assert_eq!(packages.len(), 629);
    }
}
