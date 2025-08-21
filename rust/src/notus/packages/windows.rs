// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{Package, PackageVersion};
use std::cmp::Ordering;

/// Represent a based Windows package
#[derive(Debug, PartialEq, Clone)]
pub struct Windows {
    name: String,
    prefix: String,
    build: PackageVersion,
}

impl PartialOrd for Windows {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.prefix != other.prefix || self.name != other.name {
            return None;
        }

        self.build.partial_cmp(&other.build)
    }
}

impl Package for Windows {
    fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let full_name = full_name.trim();

        let (name, version) = full_name.split_once(';')?;

        // Get all fields
        let (prefix, build) = version.rsplit_once('.')?;
        Some(Windows {
            name: name.to_string(),
            prefix: prefix.to_string(),
            build: PackageVersion(build.to_string()),
        })
    }

    fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }

        let name = name.trim();
        let version = full_version.trim();

        let (prefix, build) = version.rsplit_once('.')?;

        Some(Windows {
            name: name.to_string(),
            prefix: prefix.to_string(),
            build: PackageVersion(build.to_string()),
        })
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_version(&self) -> String {
        format!("{}.{}", self.prefix, self.build)
    }
}

#[cfg(test)]
mod slack_tests {
    use super::Package;
    use super::PackageVersion;
    use super::Windows;

    #[test]
    fn test_compare_gt() {
        let package1 = Windows {
            name: "Windows Server 2025 x64".to_string(),
            prefix: "10.0.26100".to_string(),
            build: PackageVersion("1".to_string()),
        };
        let package2 = Windows {
            name: "Windows Server 2025 x64".to_string(),
            prefix: "10.0.26100".to_string(),
            build: PackageVersion("2".to_string()),
        };
        assert!(package2 > package1);
    }

    #[test]
    fn test_compare_gt_different_name() {
        let package1 = Windows {
            name: "Windows Server 2025 x64".to_string(),
            prefix: "10.0.26100".to_string(),
            build: PackageVersion("1".to_string()),
        };
        let package2 = Windows {
            name: "Windows Server 2024 x64".to_string(),
            prefix: "10.0.26100".to_string(),
            build: PackageVersion("1".to_string()),
        };

        assert!(package2.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package2).is_none());
    }

    #[test]
    fn test_compare_gt_different_prefix() {
        let package1 = Windows {
            name: "Windows Server 2025 x64".to_string(),
            prefix: "10.0.26100".to_string(),
            build: PackageVersion("1".to_string()),
        };
        let package2 = Windows {
            name: "Windows Server 2025 x64".to_string(),
            prefix: "11.0.26100".to_string(),
            build: PackageVersion("1".to_string()),
        };

        assert!(package2.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package2).is_none());
    }

    #[test]
    fn test_compare_equal() {
        let package1 = Windows {
            name: "Windows Server 2025 x64".to_string(),
            prefix: "10.0.26100".to_string(),
            build: PackageVersion("1".to_string()),
        };
        let package2 = Windows {
            name: "Windows Server 2025 x64".to_string(),
            prefix: "10.0.26100".to_string(),
            build: PackageVersion("1".to_string()),
        };
        assert!(package1 == package2);
    }

    #[test]
    fn test_from_full_name() {
        assert!(Windows::from_full_name("").is_none());

        let package = Windows::from_full_name("Windows Server 2025 x64;10.0.26100.1000").unwrap();
        assert_eq!(package.name, "Windows Server 2025 x64");
        assert_eq!(package.prefix, "10.0.26100");
        assert_eq!(package.build, PackageVersion("1000".to_string()));
    }

    #[test]
    fn test_from_name_and_full_version() {
        assert!(Windows::from_name_and_full_version("", "").is_none());

        let package = Windows::from_name_and_full_version(
            "Windows Server 2025 (Server Core Installation) x64",
            "10.0.26100.1001",
        )
        .unwrap();
        assert_eq!(
            package.name,
            "Windows Server 2025 (Server Core Installation) x64"
        );
        assert_eq!(package.prefix, "10.0.26100");
        assert_eq!(package.build, PackageVersion("1001".to_string()));
    }
}
