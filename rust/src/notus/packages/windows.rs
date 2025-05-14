// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{Package, PackageVersion};
use std::cmp::Ordering;

/// Represent a based Windows package
#[derive(Debug, PartialEq, Clone)]
pub struct Windows {
    identifier: String,
    full_version: String,
    build: PackageVersion,
}

impl PartialOrd for Windows {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.identifier != other.identifier {
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

        // Get all fields
        let (identifier, build) = match full_name.rsplit_once('.') {
            Some((b, r)) => (b, r),
            None => {
                return None;
            }
        };
        Some(Windows {
            identifier: identifier.to_string(),
            build: PackageVersion(build.to_string()),
        })
    }

    fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }

        let version = full_version.trim();

        let (prefix, build) = match version.rsplit_once('.') {
            Some((b, r)) => (b, r),
            None => {
                return None;
            }
        };

        let mut name = name.trim().to_string();
        name.push_str(prefix);

        Some(Windows {
            identifier: name,
            build: PackageVersion(build.to_string()),
        })
    }

    fn get_name(&self) -> String {
        self.identifier.clone()
    }

    fn get_version(&self) -> String {
        self.build.0.clone()
    }
}

#[cfg(test)]
mod slack_tests {
    use super::Package;
    use super::PackageVersion;
    use super::Windows;

    #[test]
    pub fn test_compare_gt() {
        let package1 = Windows {
            build: "10.0.22631".to_string(),
            full_name: "10.0.22631.3447".to_string(),
            build: PackageVersion("3447".to_string()),
        };
        let package2 = Windows {
            build: "10.0.22631".to_string(),
            full_name: "10.0.22631.3449".to_string(),
            build: PackageVersion("3449".to_string()),
        };
        assert!(package2 > package1);

        let package1 = Windows::from_full_name("10.0.26100.0").unwrap();
        let package2 = Windows::from_full_name("10.0.26100.1").unwrap();
        assert!(package2 > package1);
    }

    #[test]
    pub fn test_compare_gt_different_name() {
        let package1 = Windows {
            build: "11.0.22631".to_string(),
            full_name: "10.0.22631.3447".to_string(),
            build: PackageVersion("3447".to_string()),
        };
        let package2 = Windows {
            build: "10.0.22631".to_string(),
            full_name: "10.0.22631.3449".to_string(),
            build: PackageVersion("3449".to_string()),
        };

        assert!(package2.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package2).is_none());
    }

    #[test]
    pub fn test_compare_less() {
        let package1 = Windows {
            build: "10.0.22631".to_string(),
            full_name: "10.0.22631.3447".to_string(),
            build: PackageVersion("3447".to_string()),
        };
        let package2 = Windows {
            build: "10.0.22631".to_string(),
            full_name: "10.0.22631.3449".to_string(),
            build: PackageVersion("3449".to_string()),
        };
        assert!(package1 < package2);
    }

    #[test]
    pub fn test_compare_equal() {
        let package1 = Windows {
            build: "10.0.22631".to_string(),
            full_name: "10.0.22631.3447".to_string(),
            build: PackageVersion("3447".to_string()),
        };
        let package2 = Windows {
            build: "10.0.22631".to_string(),
            full_name: "10.0.22631.3447".to_string(),
            build: PackageVersion("3447".to_string()),
        };
        assert!(package1 == package2);
    }

    #[test]
    pub fn test_from_full_name() {
        assert!(Windows::from_full_name("").is_none());

        let package = Windows::from_full_name("10.0.22631.3447").unwrap();
        assert_eq!(package.build, "10.0.22631");
        assert_eq!(package.full_name, "10.0.22631.3447");
        assert_eq!(package.build, PackageVersion("3447".to_string()));
    }

    #[test]
    pub fn test_from_name_and_full_version() {
        assert!(Windows::from_name_and_full_version("", "").is_none());

        let package = Windows::from_name_and_full_version("10.0.22631", "3447").unwrap();
        assert_eq!(package.build, "10.0.22631");
        assert_eq!(package.full_name, "10.0.22631.3447");
        assert_eq!(package.build, PackageVersion("3447".to_string()));
    }
}
