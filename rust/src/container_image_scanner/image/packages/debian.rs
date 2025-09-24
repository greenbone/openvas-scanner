use std::{fmt::Display, str::FromStr};

use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tracing::debug;

use super::{PackageError, ResolvePackages};
use crate::container_image_scanner::image::extractor::{Locator, LocatorError};

pub struct DPKGStatusFile;

impl DPKGStatusFile {
    /// As it is used by the extractor and we don't know the target path at compile time it needs
    /// to be relatively.
    pub(super) const fn wanted_files() -> &'static [&'static str] {
        &["var/lib/dpkg/status"]
    }
}

#[derive(Debug, Default)]
struct Package {
    package: String,
    version: String,
    status: PackageStatus,
    //architecture: String,
}

impl Display for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.package, self.version)
    }
}

impl DPKGStatusFile {
    async fn parse_file<T>(mut reader: T) -> Vec<String>
    where
        T: AsyncBufRead + Unpin,
    {
        let mut line = String::new();
        let mut result = Vec::new();
        let mut current_package = Package::default();

        loop {
            line.clear();
            let bytes = match reader.read_line(&mut line).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error=%e, "Unable to get line. Skipping rest.");
                    return result;
                }
            };
            line = line.trim().to_owned();
            if bytes == 0 || line.is_empty() {
                if current_package.status.status == Status::Installed {
                    result.push(current_package.to_string());
                } else {
                    debug!(
                        ?current_package,
                        "Ignoring package, as it is not considered as installed"
                    );
                }
                if bytes == 0 {
                    break;
                } else {
                    continue;
                }
            }

            if let Some(package) = line.strip_prefix("Package: ") {
                let package = package.to_owned();
                current_package = Package {
                    package,
                    ..Default::default()
                };
            } else if let Some(status) = line.strip_prefix("Status: ") {
                match PackageStatus::from_str(status) {
                    Ok(x) => current_package.status = x,
                    Err(e) => tracing::warn!(error=%e, line, "Unable to parse status"),
                };
            } else if let Some(version) = line.strip_prefix("Version: ") {
                current_package.version = version.to_owned();
            }
        }
        result
    }
}

impl ResolvePackages for DPKGStatusFile {
    async fn packages<T>(locator: &T) -> Result<Vec<String>, super::PackageError>
    where
        T: Locator,
    {
        let mut result = Vec::new();

        for path in Self::wanted_files() {
            match locator.locate(path).await {
                Ok(x) => result.extend(Self::parse_file(x.open().await).await),
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

#[derive(Default, Debug, PartialEq, Eq)]
struct PackageStatus {
    want: Want,
    flag: Flag,
    status: Status,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageStatusParseError {
    #[error("Missing want: `{0}`")]
    MissingWant(String),
    #[error("Missing flag: `{0}`")]
    MissingFlag(String),
    #[error("Missing status: `{0}`")]
    MissingStatus(String),
    #[error("Unknown want: `{0}`")]
    UnknownWant(String),
    #[error("Unknown flag: `{0}`")]
    UnknownFlag(String),
    #[error("Unknown status: `{0}`")]
    UnknownStatus(String),
}

impl FromStr for PackageStatus {
    type Err = PackageStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut words = value.split_whitespace();

        let want_str = words
            .next()
            .ok_or_else(|| PackageStatusParseError::MissingWant(value.into()))?;
        let flag_str = words
            .next()
            .ok_or_else(|| PackageStatusParseError::MissingFlag(value.into()))?;
        let status_str = words
            .next()
            .ok_or_else(|| PackageStatusParseError::MissingStatus(value.into()))?;

        Ok(PackageStatus {
            want: want_str.parse()?,
            flag: flag_str.parse()?,
            status: status_str.parse()?,
        })
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
enum Want {
    #[default]
    Unknown,
    Install,
    Hold,
    Deinstall,
    Purge,
}

impl FromStr for Want {
    type Err = PackageStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "install" => Ok(Want::Install),
            "hold" => Ok(Want::Hold),
            "deinstall" => Ok(Want::Deinstall),
            "purge" => Ok(Want::Purge),
            _ => Err(PackageStatusParseError::UnknownWant(value.to_owned())),
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
enum Flag {
    #[default]
    Unknown,
    Ok,
    ReInstReq,
}

impl FromStr for Flag {
    type Err = PackageStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ok" => Ok(Flag::Ok),
            "reinstreq" => Ok(Flag::ReInstReq),
            _ => Err(PackageStatusParseError::UnknownFlag(value.to_owned())),
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
enum Status {
    #[default]
    Unknown,
    NotInstalled,
    Unpacked,
    HalfConfigured,
    HalfInstalled,
    Installed,
    ConfigFiles,
    TriggersAwaiting,
    TriggersPending,
}

impl FromStr for Status {
    type Err = PackageStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "not-installed" => Ok(Status::NotInstalled),
            "unpacked" => Ok(Status::Unpacked),
            "half-configured" => Ok(Status::HalfConfigured),
            "half-installed" => Ok(Status::HalfInstalled),
            "installed" => Ok(Status::Installed),
            "config-files" => Ok(Status::ConfigFiles),
            "triggers-awaited" => Ok(Status::TriggersAwaiting),
            "triggers-pending" => Ok(Status::TriggersPending),
            _ => Err(PackageStatusParseError::UnknownStatus(value.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::container_image_scanner::image::packages::{
        ResolvePackages, debian::DPKGStatusFile, fakes::FakeLocator,
    };

    #[tokio::test]
    async fn find_packages() {
        let packages = DPKGStatusFile::packages(&FakeLocator {}).await.unwrap();
        assert!(!packages.is_empty(), "expected some packages");
    }
}
