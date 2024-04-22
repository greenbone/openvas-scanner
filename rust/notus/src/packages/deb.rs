// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{Package, PackageVersion};
use lazy_regex::{lazy_regex, Lazy, Regex};
use std::cmp::Ordering;

static RE: Lazy<Regex> = lazy_regex!(r"(.*)-(?:(\d*):)?(\d.*)-(.*)");
static RE_WO_REVISION: Lazy<Regex> = lazy_regex!(r"(.*)-(?:(\d*):)?(\d.*)");
static RE_VERSION: Lazy<Regex> = lazy_regex!(r"(?:(\d*):)?(\d.*)-(.*)");
static RE_VERSION_WO_REVISION: Lazy<Regex> = lazy_regex!(r"(?:(\d*):)?(\d.*)");

/// Represent a based Redhat package
#[derive(Debug, PartialEq, Clone)]
pub struct Deb {
    name: String,
    full_name: String,
    full_version: String,
    epoch: u64,
    upstream_version: PackageVersion,
    debian_revision: PackageVersion,
}

impl PartialOrd for Deb {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.name != other.name {
            return None;
        }

        if self.full_version == other.full_version {
            return Some(Ordering::Equal);
        }

        if self.epoch != other.epoch {
            return match self.epoch > other.epoch {
                true => Some(Ordering::Greater),
                false => Some(Ordering::Less),
            };
        };

        if let Some(comp) = self.upstream_version.partial_cmp(&other.upstream_version) {
            if comp.is_ne() {
                return Some(comp);
            }
        }

        self.debian_revision.partial_cmp(&other.debian_revision)
    }
}

impl Package for Deb {
    fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let full_name = full_name.trim();

        // Get all fields
        let (name, epochstr, upstream_version, debian_revision) = match RE.captures(full_name) {
            Some(c) => (
                c.get(1).map_or("", |m| m.as_str()),
                c.get(2).map_or("", |m| m.as_str()),
                c.get(3).map_or("", |m| m.as_str()),
                c.get(4).map_or("", |m| m.as_str()),
            ),
            None => match RE_WO_REVISION.captures(full_name) {
                None => {
                    return None;
                }
                Some(c) => (
                    c.get(1).map_or("", |m| m.as_str()),
                    c.get(2).map_or("", |m| m.as_str()),
                    c.get(3).map_or("", |m| m.as_str()),
                    "",
                ),
            },
        };

        let mut full_version = String::new();
        // parse epoch to u64. If should never fail. Therefore I let it panic
        let epoch = match epochstr.parse::<u64>() {
            Ok(n) => {
                full_version = epochstr.to_string();
                full_version.push(':');
                full_version.push_str(upstream_version);
                n
            }
            Err(_) => {
                full_version.push_str(upstream_version);
                0
            }
        };

        if !debian_revision.is_empty() {
            full_version.push('-');
            full_version.push_str(debian_revision)
        }

        Some(Deb {
            name: name.to_string(),
            full_name: full_name.to_string(),
            full_version,
            epoch,
            upstream_version: PackageVersion(upstream_version.to_string()),
            debian_revision: PackageVersion(debian_revision.to_string()),
        })
    }

    fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }

        let name = name.trim();
        let full_version = full_version.trim();

        // Get all fields
        let (epochstr, upstream_version, debian_revision) = match RE_VERSION.captures(full_version)
        {
            Some(c) => (
                c.get(1).map_or("0", |m| m.as_str()), //Defaults to 0
                c.get(2).map_or("", |m| m.as_str()),
                c.get(3).map_or("", |m| m.as_str()),
            ),
            None => match RE_VERSION_WO_REVISION.captures(full_version) {
                None => {
                    return None;
                }
                Some(c) => (
                    c.get(1).map_or("0", |m| m.as_str()), //Defaults to 0
                    c.get(2).map_or("", |m| m.as_str()),
                    "",
                ),
            },
        };

        // parse epoch to u64. If should never fail. Therefore I let it panic
        let epoch = epochstr.parse::<u64>().unwrap();

        let mut full_name = name.to_owned();
        full_name.push('-');
        full_name.push_str(full_version);

        Some(Deb {
            name: name.to_string(),
            full_name: full_name.to_string(),
            full_version: full_version.to_string(),
            epoch,
            upstream_version: PackageVersion(upstream_version.to_string()),
            debian_revision: PackageVersion(debian_revision.to_string()),
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
mod deb_tests {
    use crate::packages::{self, PackageVersion};

    use super::{Deb, Package};

    #[test]
    pub fn test_compare_gt() {
        let package1 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-bar-1:1.2.3-4".to_string(),
            full_version: "1:1.2.3-4".to_string(),
        };
        let package2 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.4".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-bar-1:1.2.4-4".to_string(),
            full_version: "1:1.2.4-4".to_string(),
        };
        assert!(package2 > package1);

        let package2 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("5".to_string()),
            full_name: "foo-bar-1:1.2.3-5".to_string(),
            full_version: "1:1.2.3-5".to_string(),
        };
        assert!(package2 > package1);
    }

    #[test]
    pub fn test_compare_gt_different_name() {
        let package1 = Deb {
            name: "foo".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-1:1.2.3-4".to_string(),
            full_version: "1:1.2.3-4".to_string(),
        };
        let package2 = Deb {
            name: "bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "bar-1:1.2.3-4".to_string(),
            full_version: "1:1.2.3-4".to_string(),
        };
        assert!(package2.partial_cmp(&package1).is_none());
    }

    #[test]
    pub fn test_compare_less() {
        let package1 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-bar-1:1.2.3-4".to_string(),
            full_version: "1:1.2.3-4".to_string(),
        };
        let package2 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.4".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-bar-1:1.2.4-4".to_string(),
            full_version: "1:1.2.4-4".to_string(),
        };
        assert!(package1 < package2);

        let package2 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("5".to_string()),
            full_name: "foo-bar-1.2.3-5:1".to_string(),
            full_version: "1:1.2.3-5".to_string(),
        };
        assert!(package1 < package2);

        let package2 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3~rc".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-bar-1:1.2.3~rc-4".to_string(),
            full_version: "1:1.2.3~rc-4".to_string(),
        };
        assert!(package2 < package1);
    }

    #[test]
    pub fn test_compare_equal() {
        let package1 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-bar-1:1.2.3-4".to_string(),
            full_version: "1:1.2.3-4".to_string(),
        };
        let package2 = Deb {
            name: "foo-bar".to_string(),
            epoch: 1,
            upstream_version: packages::PackageVersion("1.2.3".to_string()),
            debian_revision: packages::PackageVersion("4".to_string()),
            full_name: "foo-bar-1:1.2.3-4".to_string(),
            full_version: "1:1.2.3-4".to_string(),
        };
        assert!(package1 == package2);
    }

    #[test]
    pub fn test_from_full_name() {
        assert!(Deb::from_full_name("").is_none());

        let package = Deb::from_full_name("mesa-libgbm-2:11.2.2-2.20160614").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 2);
        assert_eq!(
            package.upstream_version,
            PackageVersion("11.2.2".to_string())
        );
        assert_eq!(
            package.debian_revision,
            PackageVersion("2.20160614".to_string())
        );
        assert_eq!(package.full_name, "mesa-libgbm-2:11.2.2-2.20160614");
        assert_eq!(package.full_version, "2:11.2.2-2.20160614");

        let package = Deb::from_full_name("keyutils-1.5.8-3").unwrap();
        assert_eq!(package.name, "keyutils");
        assert_eq!(package.epoch, 0);
        assert_eq!(
            package.upstream_version,
            PackageVersion("1.5.8".to_string())
        );
        assert_eq!(package.debian_revision, PackageVersion("3".to_string()));
        assert_eq!(package.full_name, "keyutils-1.5.8-3");
        assert_eq!(package.full_version, "1.5.8-3");

        let package = Deb::from_full_name("httpd-manual-1:2.4.6-45.0.1.4.h10").unwrap();
        assert_eq!(package.name, "httpd-manual");
        assert_eq!(package.epoch, 1);
        assert_eq!(
            package.upstream_version,
            PackageVersion("2.4.6".to_string())
        );
        assert_eq!(
            package.debian_revision,
            PackageVersion("45.0.1.4.h10".to_string())
        );
        assert_eq!(package.full_name, "httpd-manual-1:2.4.6-45.0.1.4.h10");

        let package = Deb::from_full_name("libzstd1-1.3.8+dfsg-3+deb10u2").unwrap();
        assert_eq!(package.name, "libzstd1");
        assert_eq!(package.epoch, 0);
        assert_eq!(
            package.upstream_version,
            PackageVersion("1.3.8+dfsg".to_string())
        );
        assert_eq!(
            package.debian_revision,
            PackageVersion("3+deb10u2".to_string())
        );
        assert_eq!(package.full_name, "libzstd1-1.3.8+dfsg-3+deb10u2");

        let package =
            Deb::from_full_name("xserver-xorg-video-intel-2:2.99.917+git20180925-2").unwrap();
        assert_eq!(package.name, "xserver-xorg-video-intel");
        assert_eq!(package.epoch, 2);
        assert_eq!(
            package.upstream_version,
            PackageVersion("2.99.917+git20180925".to_string())
        );
        assert_eq!(package.debian_revision, PackageVersion("2".to_string()));
        assert_eq!(
            package.full_name,
            "xserver-xorg-video-intel-2:2.99.917+git20180925-2",
        );

        let package = Deb::from_full_name("ucf-3.0038+nmu1").unwrap();
        assert_eq!(package.name, "ucf");
        assert_eq!(package.epoch, 0);
        assert_eq!(
            package.upstream_version,
            PackageVersion("3.0038+nmu1".to_string())
        );
        assert_eq!(package.debian_revision, PackageVersion("".to_string()));
        assert_eq!(package.full_name, "ucf-3.0038+nmu1");

        let package = Deb::from_full_name("apport-symptoms-020").unwrap();
        assert_eq!(package.name, "apport-symptoms");
        assert_eq!(package.epoch, 0);
        assert_eq!(package.upstream_version, PackageVersion("020".to_string()));
        assert_eq!(package.debian_revision, PackageVersion("".to_string()));
        assert_eq!(package.full_name, "apport-symptoms-020");
    }
    #[test]
    pub fn from_name_and_full_version() {
        assert!(Deb::from_name_and_full_version("", "").is_none());

        let package =
            Deb::from_name_and_full_version("mesa-libgbm", "2:11.2.2-2.20160614").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 2);
        assert_eq!(
            package.upstream_version,
            PackageVersion("11.2.2".to_string())
        );
        assert_eq!(
            package.debian_revision,
            PackageVersion("2.20160614".to_string())
        );
        assert_eq!(package.full_name, "mesa-libgbm-2:11.2.2-2.20160614");
        assert_eq!(package.full_version, "2:11.2.2-2.20160614");

        let package = Deb::from_name_and_full_version("mesa-libgbm", "2:11.2.2").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 2);
        assert_eq!(
            package.upstream_version,
            PackageVersion("11.2.2".to_string())
        );
        assert_eq!(package.debian_revision, PackageVersion("".to_string()));
        assert_eq!(package.full_name, "mesa-libgbm-2:11.2.2");
        assert_eq!(package.full_version, "2:11.2.2");

        let package = Deb::from_name_and_full_version("mesa-libgbm", "11.2.2").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 0);
        assert_eq!(
            package.upstream_version,
            PackageVersion("11.2.2".to_string())
        );
        assert_eq!(package.debian_revision, PackageVersion("".to_string()));
        assert_eq!(package.full_name, "mesa-libgbm-11.2.2");
        assert_eq!(package.full_version, "11.2.2");

        let package = Deb::from_name_and_full_version("mesa-libgbm", "11.2.2-2.20160614").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 0);
        assert_eq!(
            package.upstream_version,
            PackageVersion("11.2.2".to_string())
        );
        assert_eq!(
            package.debian_revision,
            PackageVersion("2.20160614".to_string())
        );
        assert_eq!(package.full_name, "mesa-libgbm-11.2.2-2.20160614");
        assert_eq!(package.full_version, "11.2.2-2.20160614");
    }
}
