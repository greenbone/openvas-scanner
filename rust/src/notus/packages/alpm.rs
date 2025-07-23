// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use lazy_regex::{Lazy, lazy_regex};
use regex::Regex;

use super::{Package, PackageVersion};

static RE: Lazy<Regex> = lazy_regex!(
    r"^(?x)
    (?:
        (?P<epoch>
            \d+
        )
        :
    )?
    (?P<pkgver>
        [^:\/\s-]+
    )
    (?:
        -
        (?P<pkgrel>
            \d+
            (?:
                .\d+
            )?
        )
    )?
    $"
);

/// Represent a Arch Linux / ALPM based package
#[derive(Debug, PartialEq, Clone)]
pub struct Alpm {
    name: String,
    epoch: u64,
    pkgver: PackageVersion,
    pkgrel: PackageVersion,
}

impl PartialOrd for Alpm {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.name != other.name {
            return None;
        }

        (&self.epoch, &self.pkgver, &self.pkgrel).partial_cmp(&(
            &other.epoch,
            &other.pkgver,
            &other.pkgrel,
        ))
    }
}

impl Package for Alpm {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_version(&self) -> String {
        format!("{}:{}-{}", self.epoch, self.pkgver, self.pkgrel)
    }

    fn from_full_name(full_name: &str) -> Option<Self> {
        full_name
            .split_once(" ")
            .and_then(|(name, version)| Self::from_name_and_full_version(name, version))
    }

    fn from_name_and_full_version(name: &str, version: &str) -> Option<Self> {
        let captures = RE.captures(version)?;

        let epoch = captures
            .name("epoch")
            .map(|m| m.as_str().parse().unwrap_or(0))
            .unwrap_or(0);

        let pkgver = captures
            .name("pkgver")
            .map(|m| m.as_str())
            // Cannot fail, because the regex ensures that there is a pkgver
            .unwrap()
            .into();

        let pkgrel = captures
            .name("pkgrel")
            .map(|m| m.as_str())
            .unwrap_or_else(|| ("1"))
            .into();

        Some(Self {
            name: name.to_string(),
            epoch,
            pkgver,
            pkgrel,
        })
    }
}

#[cfg(test)]
mod deb_tests {
    use super::PackageVersion;

    use super::{Alpm, Package};

    #[test]
    fn test_compare_gt() {
        let package1 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        let package2 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.4".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        assert!(package2 > package1);

        let package2 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("5".to_string()),
        };
        assert!(package2 > package1);
    }

    #[test]
    fn test_compare_gt_different_name() {
        let package1 = Alpm {
            name: "foo".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        let package2 = Alpm {
            name: "bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        assert!(package2.partial_cmp(&package1).is_none());
    }

    #[test]
    fn test_compare_less() {
        let package1 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        let package2 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.4".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        assert!(package1 < package2);

        let package2 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("5".to_string()),
        };
        assert!(package1 < package2);
    }

    #[test]
    fn test_compare_equal() {
        let package1 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        let package2 = Alpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            pkgver: PackageVersion("1.2.3".to_string()),
            pkgrel: PackageVersion("4".to_string()),
        };
        assert!(package1 == package2);
    }

    #[test]
    fn test_from_full_name() {
        assert!(Alpm::from_full_name("").is_none());

        let package = Alpm::from_full_name("mesa-libgbm 2:11.2.2-2.20160614").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 2);
        assert_eq!(package.pkgver, PackageVersion("11.2.2".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("2.20160614".to_string()));
        assert_eq!(package.get_version(), "2:11.2.2-2.20160614");

        let package = Alpm::from_full_name("keyutils 1.5.8-3").unwrap();
        assert_eq!(package.name, "keyutils");
        assert_eq!(package.epoch, 0);
        assert_eq!(package.pkgver, PackageVersion("1.5.8".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("3".to_string()));
        assert_eq!(package.get_version(), "0:1.5.8-3");

        let package = Alpm::from_full_name("httpd-manual 1:2.4.6-45.0").unwrap();
        assert_eq!(package.name, "httpd-manual");
        assert_eq!(package.epoch, 1);
        assert_eq!(package.pkgver, PackageVersion("2.4.6".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("45.0".to_string()));
        assert_eq!(package.get_version(), "1:2.4.6-45.0");

        let package = Alpm::from_full_name("libzstd1 1.3.8+dfsg-3.10").unwrap();
        assert_eq!(package.name, "libzstd1");
        assert_eq!(package.epoch, 0);
        assert_eq!(package.pkgver, PackageVersion("1.3.8+dfsg".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("3.10".to_string()));
        assert_eq!(package.get_version(), "0:1.3.8+dfsg-3.10");

        let package =
            Alpm::from_full_name("xserver-xorg-video-intel 2:2.99.917+git20180925-2").unwrap();
        assert_eq!(package.name, "xserver-xorg-video-intel");
        assert_eq!(package.epoch, 2);
        assert_eq!(
            package.pkgver,
            PackageVersion("2.99.917+git20180925".to_string())
        );
        assert_eq!(package.pkgrel, PackageVersion("2".to_string()));
        assert_eq!(package.get_version(), "2:2.99.917+git20180925-2");

        let package = Alpm::from_full_name("ucf 3.0038+nmu1").unwrap();
        assert_eq!(package.name, "ucf");
        assert_eq!(package.epoch, 0);
        assert_eq!(package.pkgver, PackageVersion("3.0038+nmu1".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("1".to_string()));
        assert_eq!(package.get_version(), "0:3.0038+nmu1-1");

        let package = Alpm::from_full_name("apport-symptoms 020").unwrap();
        assert_eq!(package.name, "apport-symptoms");
        assert_eq!(package.epoch, 0);
        assert_eq!(package.pkgver, PackageVersion("020".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("1".to_string()));
        assert_eq!(package.get_version(), "0:020-1");

        let package = Alpm::from_full_name("mariadb-server-10.6 1:10.6.18+maria~ubu2204").unwrap();
        assert_eq!(package.name, "mariadb-server-10.6");
        assert_eq!(package.epoch, 1);
        assert_eq!(
            package.pkgver,
            PackageVersion("10.6.18+maria~ubu2204".to_string())
        );
        assert_eq!(package.pkgrel, PackageVersion("1".to_string()));
        assert_eq!(package.get_version(), "1:10.6.18+maria~ubu2204-1");
    }
    #[test]
    fn from_name_and_full_version() {
        assert!(Alpm::from_name_and_full_version("", "").is_none());

        let package =
            Alpm::from_name_and_full_version("mesa-libgbm", "2:11.2.2-2.20160614").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 2);
        assert_eq!(package.pkgver, PackageVersion("11.2.2".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("2.20160614".to_string()));
        assert_eq!(package.get_version(), "2:11.2.2-2.20160614");

        let package = Alpm::from_name_and_full_version("mesa-libgbm", "2:11.2.2").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 2);
        assert_eq!(package.pkgver, PackageVersion("11.2.2".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("1".to_string()));
        assert_eq!(package.get_version(), "2:11.2.2-1");

        let package = Alpm::from_name_and_full_version("mesa-libgbm", "11.2.2").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 0);
        assert_eq!(package.pkgver, PackageVersion("11.2.2".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("1".to_string()));
        assert_eq!(package.get_version(), "0:11.2.2-1");

        let package = Alpm::from_name_and_full_version("mesa-libgbm", "11.2.2-2.20160614").unwrap();
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.epoch, 0);
        assert_eq!(package.pkgver, PackageVersion("11.2.2".to_string()));
        assert_eq!(package.pkgrel, PackageVersion("2.20160614".to_string()));
        assert_eq!(package.get_version(), "0:11.2.2-2.20160614");
    }
}
