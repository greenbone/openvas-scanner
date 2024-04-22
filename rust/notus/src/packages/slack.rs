// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{Package, PackageVersion};
use lazy_regex::{lazy_regex, Lazy, Regex};
use std::cmp::Ordering;

static RE: Lazy<Regex> = lazy_regex!(r"(..*)-(..*)-(..*)-(\d)(?:_slack(..*))?");
static RE_VERSION: Lazy<Regex> = lazy_regex!(r"(..*)-(..*)-(\d)(?:_slack(..*))?");

/// Represent a based Redhat package
#[derive(Debug, PartialEq, Clone)]
pub struct Slack {
    name: String,
    full_name: String,
    full_version: String,
    build: PackageVersion,
    target: PackageVersion,
    version: PackageVersion,
    arch: String,
}

impl PartialOrd for Slack {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.name != other.name {
            return None;
        }

        if self.arch != other.arch {
            return None;
        }

        if self.full_version == other.full_version {
            return Some(Ordering::Equal);
        }

        if let Some(comp) = self.version.partial_cmp(&other.version) {
            if comp.is_ne() {
                return Some(comp);
            }
        }

        if let Some(comp) = self.target.partial_cmp(&other.target) {
            if comp.is_ne() {
                return Some(comp);
            }
        }

        self.build.partial_cmp(&other.build)
    }
}

impl Package for Slack {
    fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let full_name = full_name.trim();

        // Get all fields
        let (name, version, arch, build, target) = match RE.captures(full_name) {
            Some(c) => (
                c.get(1).map_or("", |m| m.as_str()),
                c.get(2).map_or("", |m| m.as_str()),
                c.get(3).map_or("", |m| m.as_str()),
                c.get(4).map_or("", |m| m.as_str()),
                c.get(5).map_or("", |m| m.as_str()),
            ),
            None => {
                return None;
            }
        };

        let mut full_version = version.to_string();
        full_version.push('-');
        full_version.push_str(arch);
        full_version.push('-');
        full_version.push_str(build);

        if !target.is_empty() {
            full_version.push_str("_slack");
            full_version.push_str(target);
        }

        Some(Slack {
            name: name.to_string(),
            full_name: full_name.to_string(),
            full_version,
            target: PackageVersion(target.to_string()),
            build: PackageVersion(build.to_string()),
            version: PackageVersion(version.to_string()),
            arch: arch.to_string(),
        })
    }

    fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }

        let name = name.trim();
        let full_version = full_version.trim();

        // Get all fields
        let (version, arch, build, target) = match RE_VERSION.captures(full_version) {
            Some(c) => (
                c.get(1).map_or("", |m| m.as_str()),
                c.get(2).map_or("", |m| m.as_str()),
                c.get(3).map_or("", |m| m.as_str()),
                c.get(4).map_or("", |m| m.as_str()),
            ),
            None => {
                return None;
            }
        };

        let mut full_name = name.to_string();
        full_name.push('-');
        full_name.push_str(full_version);

        Some(Slack {
            name: name.to_string(),
            full_name,
            full_version: full_version.to_string(),
            target: PackageVersion(target.to_string()),
            build: PackageVersion(build.to_string()),
            version: PackageVersion(version.to_string()),
            arch: arch.to_string(),
        })
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_version(&self) -> String {
        self.full_version.clone()
    }
}

#[cfg(test)]
mod slack_tests {
    use crate::packages::PackageVersion;

    use super::Package;
    use super::Slack;

    #[test]
    pub fn test_compare_gt() {
        let package1 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.0".to_string(),
        };
        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.4".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.4-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.4-x86_64-4_slack15.0".to_string(),
        };
        assert!(package2 > package1);

        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("5".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-5_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-5_slack15.0".to_string(),
        };
        assert!(package2 > package1);

        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.1".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-4_slack15.1".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.1".to_string(),
        };
        assert!(package2 > package1);
    }

    #[test]
    pub fn test_compare_gt_different_architecture() {
        let package1 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.0".to_string(),
        };
        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "aarch64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-aarch64-4_slack15.0".to_string(),
            full_version: "1.2.3-aarch64-4_slack15.0".to_string(),
        };
        let package3 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.4".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "aarch64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.4-aarch64-4_slack15.0".to_string(),
            full_version: "1.2.4-aarch64-4_slack15.0".to_string(),
        };
        let package4 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("5".to_string()),
            arch: "aarch64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-aarch64-5_slack15.0".to_string(),
            full_version: "1.2.3-aarch64-5_slack15.0".to_string(),
        };
        let package5 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "aarch64".to_string(),
            target: PackageVersion("15.1".to_string()),
            full_name: "foo-bar-1.2.3-aarch64-4_slack15.1".to_string(),
            full_version: "1.2.3-aarch64-4_slack15.1".to_string(),
        };

        assert!(package2.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package2).is_none());
        assert!(package3.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package3).is_none());
        assert!(package4.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package4).is_none());
        assert!(package5.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package5).is_none());
    }

    #[test]
    pub fn test_compare_gt_different_name() {
        let package1 = Slack {
            name: "foo".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-1.2.3-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.0".to_string(),
        };
        let package2 = Slack {
            name: "bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "bar-1.2.3-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.0".to_string(),
        };

        assert!(package2.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package2).is_none());
    }

    #[test]
    pub fn test_compare_less() {
        let package1 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.0".to_string(),
        };
        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.4".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.4-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.4-x86_64-4_slack15.0".to_string(),
        };
        assert!(package1 < package2);

        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("5".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-5_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-5_slack15.0".to_string(),
        };
        assert!(package1 < package2);

        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.1".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-4_slack15.1".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.1".to_string(),
        };
        assert!(package1 < package2);
    }

    #[test]
    pub fn test_compare_equal() {
        let package1 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.0".to_string(),
        };
        let package2 = Slack {
            name: "foo-bar".to_string(),
            version: PackageVersion("1.2.3".to_string()),
            build: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            target: PackageVersion("15.0".to_string()),
            full_name: "foo-bar-1.2.3-x86_64-4_slack15.0".to_string(),
            full_version: "1.2.3-x86_64-4_slack15.0".to_string(),
        };
        assert!(package1 == package2);
    }

    #[test]
    pub fn test_from_full_name() {
        assert!(Slack::from_full_name("").is_none());

        let package = Slack::from_full_name("flac-1.3.4-foo-1_slack15.0").unwrap();
        assert_eq!(package.arch, "foo");

        let package = Slack::from_full_name("flac-1.3.4-x86_64-1_slack15.0").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "flac");
        assert_eq!(package.version, PackageVersion("1.3.4".to_string()));
        assert_eq!(package.build, PackageVersion("1".to_string()));
        assert_eq!(package.target, PackageVersion("15.0".to_string()));
        assert_eq!(package.full_version, "1.3.4-x86_64-1_slack15.0");
        assert_eq!(package.full_name, "flac-1.3.4-x86_64-1_slack15.0");

        let package = Slack::from_full_name("kernel-source-5.15.27-noarch-1").unwrap();
        assert_eq!(package.arch, "noarch");
        assert_eq!(package.name, "kernel-source");
        assert_eq!(package.version, PackageVersion("5.15.27".to_string()));
        assert_eq!(package.build, PackageVersion("1".to_string()));
        assert_eq!(package.target, PackageVersion("".to_string()));
        assert_eq!(package.full_version, "5.15.27-noarch-1");
        assert_eq!(package.full_name, "kernel-source-5.15.27-noarch-1");

        let package = Slack::from_full_name("libjpeg-v8a-x86_64-2").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "libjpeg");
        assert_eq!(package.version, PackageVersion("v8a".to_string()));
        assert_eq!(package.build, PackageVersion("2".to_string()));
        assert_eq!(package.target, PackageVersion("".to_string()));
        assert_eq!(package.full_version, "v8a-x86_64-2");
        assert_eq!(package.full_name, "libjpeg-v8a-x86_64-2");

        let package = Slack::from_full_name(" libjpeg-v8a-x86_64-2\r\n").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "libjpeg");
        assert_eq!(package.version, PackageVersion("v8a".to_string()));
        assert_eq!(package.build, PackageVersion("2".to_string()));
        assert_eq!(package.target, PackageVersion("".to_string()));
        assert_eq!(package.full_version, "v8a-x86_64-2");
        assert_eq!(package.full_name, "libjpeg-v8a-x86_64-2");

        let package = Slack::from_full_name("libjpeg-v8a-x86_64");
        assert!(package.is_none());

        let package = Slack::from_full_name("libjpeg-v8a-foo-2").unwrap();
        assert_eq!(package.arch, "foo");
    }

    #[test]
    pub fn test_from_name_and_full_version() {
        assert!(Slack::from_name_and_full_version("", "").is_none());

        let package =
            Slack::from_name_and_full_version("flac", "1.3.4-x86_64-1_slack15.0").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "flac");
        assert_eq!(package.version, PackageVersion("1.3.4".to_string()));
        assert_eq!(package.build, PackageVersion("1".to_string()));
        assert_eq!(package.target, PackageVersion("15.0".to_string()));
        assert_eq!(package.full_version, "1.3.4-x86_64-1_slack15.0");
        assert_eq!(package.full_name, "flac-1.3.4-x86_64-1_slack15.0");

        let package = Slack::from_name_and_full_version("flac", "1.3.4-x86_64");
        assert!(package.is_none());

        let package = Slack::from_name_and_full_version("flac", "1.3.4-foo-1").unwrap();
        assert_eq!(package.arch, "foo");
    }
}
