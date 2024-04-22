// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{Package, PackageVersion};
use lazy_regex::{lazy_regex, Lazy, Regex};
use std::cmp::Ordering;

static RE: Lazy<Regex> = lazy_regex!(r"^(.*)-(?:(\d+):)?([^-]+)-([^-]+)\.([^-]+)$");
static RE_VERSION: Lazy<Regex> = lazy_regex!(r"^(?:(\d+):)?([^-]+)-([^-]+)\.([^-]+)$");

/// Represent a based Redhat package
#[derive(Debug, PartialEq, Clone)]
pub struct Rpm {
    name: String,
    full_name: String,
    full_version: String,
    epoch: u64,
    version: PackageVersion,
    release: PackageVersion,
    arch: String,
}

static EXCEPTIONS: [&str; 2] = ["_fips", ".ksplice"];

impl PartialOrd for Rpm {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.name != other.name {
            return None;
        }
        if self.arch != other.arch {
            return None;
        }
        for e in EXCEPTIONS {
            let a = self.full_version.find(e);
            let b = other.full_version.find(e);
            if a.is_some() != b.is_some() {
                return None;
            }
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

        if let Some(comp) = self.version.partial_cmp(&other.version) {
            if comp.is_ne() {
                return Some(comp);
            }
        }

        self.release.partial_cmp(&other.release)
    }
}

impl Package for Rpm {
    fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let full_name = full_name.trim();

        // Get all fields
        let (name, epochstr, version, release, arch) = match RE.captures(full_name) {
            None => {
                return None;
            }
            Some(c) => (
                c.get(1).map_or("", |m| m.as_str()),
                c.get(2).map_or("0", |m| m.as_str()), //Defaults to 0
                c.get(3).map_or("", |m| m.as_str()),
                c.get(4).map_or("", |m| m.as_str()),
                c.get(5).map_or("", |m| m.as_str()),
            ),
        };
        // parse epoch to u64. If should never fail. Therefore I let it panic
        let epoch = epochstr.parse::<u64>().unwrap();

        let mut full_version = epochstr.to_owned();
        full_version.push(':');
        full_version.push_str(version);
        full_version.push('-');
        full_version.push_str(release);
        full_version.push('.');
        full_version.push_str(arch);

        Some(Rpm {
            name: name.to_string(),
            full_name: full_name.to_string(),
            full_version,
            epoch,
            version: PackageVersion(version.to_string()),
            release: PackageVersion(release.to_string()),
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
        let (epochstr, version, release, arch) = match RE_VERSION.captures(full_version) {
            None => {
                return None;
            }
            Some(c) => (
                c.get(1).map_or("0", |m| m.as_str()), //Defaults to 0
                c.get(2).map_or("", |m| m.as_str()),
                c.get(3).map_or("", |m| m.as_str()),
                c.get(4).map_or("", |m| m.as_str()),
            ),
        };

        // parse epoch to u64. If should never fail. Therefore I let it panic
        let epoch = epochstr.parse::<u64>().unwrap();

        let mut full_name = name.to_owned();
        full_name.push('-');
        full_name.push_str(full_version);

        Some(Rpm {
            name: name.to_string(),
            full_name: full_name.to_string(),
            full_version: full_version.to_string(),
            epoch,
            version: PackageVersion(version.to_string()),
            release: PackageVersion(release.to_string()),
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
mod rpm_tests {
    use crate::packages::PackageVersion;

    use super::Package;
    use super::Rpm;

    #[test]
    pub fn test_from_full_name() {
        assert!(Rpm::from_full_name("").is_none());

        assert_eq!(
            Rpm::from_full_name("keyutils-1.5.8-3.amd64").unwrap().arch,
            "amd64"
        );

        assert_eq!(
            Rpm::from_full_name("keyutils-1.5.8-3.noarch").unwrap().arch,
            "noarch"
        );

        let package = Rpm::from_full_name("mesa-libgbm-11.2.2-2.20160614.x86_64").unwrap();

        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "mesa-libgbm");
        assert_eq!(package.version, PackageVersion("11.2.2".to_string()));
        assert_eq!(package.release, PackageVersion("2.20160614".to_string()));
        assert_eq!(package.full_name, "mesa-libgbm-11.2.2-2.20160614.x86_64");

        let package = Rpm::from_full_name("keyutils-1.5.8-3.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "keyutils");
        assert_eq!(package.version, PackageVersion("1.5.8".to_string()));
        assert_eq!(package.release, PackageVersion("3".to_string()));
        assert_eq!(package.full_name, "keyutils-1.5.8-3.x86_64");

        let package = Rpm::from_full_name("httpd-manual-2.4.6-45.0.1.4.h10.noarch").unwrap();
        assert_eq!(package.arch, "noarch");
        assert_eq!(package.name, "httpd-manual");
        assert_eq!(package.version, PackageVersion("2.4.6".to_string()));
        assert_eq!(package.release, PackageVersion("45.0.1.4.h10".to_string()));
        assert_eq!(package.full_name, "httpd-manual-2.4.6-45.0.1.4.h10.noarch");

        let package = Rpm::from_full_name("cups-libs-1.6.3-26.h1.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "cups-libs");
        assert_eq!(package.version, PackageVersion("1.6.3".to_string()));
        assert_eq!(package.release, PackageVersion("26.h1".to_string()));
        assert_eq!(package.full_name, "cups-libs-1.6.3-26.h1.x86_64");

        let package = Rpm::from_full_name("GConf2-3.2.6-8.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "GConf2");
        assert_eq!(package.version, PackageVersion("3.2.6".to_string()));
        assert_eq!(package.release, PackageVersion("8".to_string()));
        assert_eq!(package.full_name, "GConf2-3.2.6-8.x86_64");

        let package = Rpm::from_full_name("libtool-ltdl-2.4.2-21.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "libtool-ltdl");
        assert_eq!(package.version, PackageVersion("2.4.2".to_string()));
        assert_eq!(package.release, PackageVersion("21".to_string()));
        assert_eq!(package.full_name, "libtool-ltdl-2.4.2-21.x86_64");

        let package = Rpm::from_full_name("microcode_ctl-2.1-22.6.h2.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "microcode_ctl");
        assert_eq!(package.version, PackageVersion("2.1".to_string()));
        assert_eq!(package.release, PackageVersion("22.6.h2".to_string()));
        assert_eq!(package.full_name, "microcode_ctl-2.1-22.6.h2.x86_64");

        let package = Rpm::from_full_name("postgresql-libs-9.2.23-3.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "postgresql-libs");
        assert_eq!(package.version, PackageVersion("9.2.23".to_string()));
        assert_eq!(package.release, PackageVersion("3".to_string()));
        assert_eq!(package.full_name, "postgresql-libs-9.2.23-3.x86_64");

        let package = Rpm::from_full_name("NetworkManager-1.8.0-9.h2.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "NetworkManager");
        assert_eq!(package.version, PackageVersion("1.8.0".to_string()));
        assert_eq!(package.release, PackageVersion("9.h2".to_string()));
        assert_eq!(package.full_name, "NetworkManager-1.8.0-9.h2.x86_64");

        let package = Rpm::from_full_name("perl-Pod-Escapes-1.04-285.h2.noarch").unwrap();
        assert_eq!(package.arch, "noarch");
        assert_eq!(package.name, "perl-Pod-Escapes");
        assert_eq!(package.version, PackageVersion("1.04".to_string()));
        assert_eq!(package.release, PackageVersion("285.h2".to_string()));
        assert_eq!(package.full_name, "perl-Pod-Escapes-1.04-285.h2.noarch");

        let package = Rpm::from_full_name(" libtool-ltdl-2.4.2-21.x86_64\r\n").unwrap();
        assert_eq!(package.arch, "x86_64");

        let package =
            Rpm::from_full_name("docker-engine-1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64")
                .unwrap();
        assert_eq!(
            package.full_name,
            "docker-engine-1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64",
        );
        assert_eq!(
            package.full_version,
            "1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64"
        );
        assert_eq!(package.epoch, 1);
        assert_eq!(package.version, PackageVersion("18.09.0".to_string()));
        assert_eq!(
            package.release,
            PackageVersion("200.h62.33.19.eulerosv2r10".to_string())
        );
        assert_eq!(package.arch, "x86_64");
    }

    #[test]
    pub fn test_exceptions() {
        let package1 = Rpm::from_full_name("gnutls-3.6.16-4.el8.x86_64").unwrap();
        let package2 = Rpm::from_full_name("gnutls-3.6.16-4.0.1.el8_fips.x86_64").unwrap();

        assert!(package1.partial_cmp(&package2).is_none());
        assert!(package2.partial_cmp(&package1).is_none());

        let package1 = Rpm::from_full_name("gnutls-3.6.16-4.el8_fips.x86_64").unwrap();
        assert!(package2 > package1);

        let package1 = Rpm::from_full_name("openssl-libs-1.0.2k-24.0.3.el7_8.x86_64").unwrap();
        let package2 =
            Rpm::from_full_name("openssl-libs-1.0.2k-24.0.3.ksplice1.el7_9.x86_64").unwrap();
        assert!(package1.partial_cmp(&package2).is_none());
        assert!(package2.partial_cmp(&package1).is_none());

        let package1 =
            Rpm::from_full_name("openssl-libs-1.0.2k-24.0.3.ksplice1.el7_8.x86_64").unwrap();
        assert!(package2 > package1);
    }

    #[test]
    pub fn test_compare_gt() {
        let package1 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.3-4.x86_64".to_string(),
            full_version: "1.2.3-4.x86_64".to_string(),
        };
        let package2 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.4".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.4-4.x86_64".to_string(),
            full_version: "1.2.4-4.x86_64".to_string(),
        };
        assert!(package2 > package1);

        let package2 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("5".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.3-5.x86_64".to_string(),
            full_version: "1.2.3-5.x86_64".to_string(),
        };
        assert!(package2 > package1);
    }

    #[test]
    pub fn test_compare_gt_different_architecture() {
        let package1 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.3-4.x86_64".to_string(),
            full_version: "1.2.3-4.x86_64".to_string(),
        };
        let package2 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "aarch64".to_string(),
            full_name: "foo-bar-1.2.3-4.aarch64".to_string(),
            full_version: "1.2.3-4.aarch64".to_string(),
        };
        let package3 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.4".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "aarch64".to_string(),
            full_name: "foo-bar-1.2.4-4.aarch64".to_string(),
            full_version: "1.2.4-4.aarch64".to_string(),
        };
        let package4 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("5".to_string()),
            arch: "aarch64".to_string(),
            full_name: "foo-bar-1.2.3-5.aarch64".to_string(),
            full_version: "1.2.3-5.aarch64".to_string(),
        };
        //Not comparable, because different archs. Compare returns None.
        assert!(package2.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package2).is_none());
        assert!(package3.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package3).is_none());
        assert!(package4.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package4).is_none());
    }

    #[test]
    pub fn test_compare_gt_different_epoch() {
        let package1 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.3-4.x86_64".to_string(),
            full_version: "1.2.3-4.x86_64".to_string(),
        };
        let package2 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 1,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.3-4.x86_64".to_string(),
            full_version: "1:1.2.3-4.x86_64".to_string(),
        };
        assert!(package2 > package1);
    }

    #[test]
    pub fn test_compare_gt_different_name() {
        let package1 = Rpm {
            name: "foo".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-1.2.3-4.x86_64".to_string(),
            full_version: "1.2.3-4.x86_64".to_string(),
        };
        let package2 = Rpm {
            name: "bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "bar-1.2.3-4.x86_64".to_string(),
            full_version: "1.2.3-4.x86_64".to_string(),
        };
        assert!(package2.partial_cmp(&package1).is_none());
        assert!(package1.partial_cmp(&package2).is_none());
    }

    #[test]
    pub fn test_compare_less() {
        let package1 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.3-4.x86_64".to_string(),
            full_version: "1.2.3-4.x86_64".to_string(),
        };
        let package2 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.4".to_string()),
            release: PackageVersion("4".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.4-4.x86_64".to_string(),
            full_version: "1.2.4-4.x86_64".to_string(),
        };
        assert!(package1 < package2);

        let package2 = Rpm {
            name: "foo-bar".to_string(),
            epoch: 0,
            version: PackageVersion("1.2.3".to_string()),
            release: PackageVersion("5".to_string()),
            arch: "x86_64".to_string(),
            full_name: "foo-bar-1.2.3-5.x86_64".to_string(),
            full_version: "1.2.3-5.x86_64".to_string(),
        };
        assert!(package1 < package2);
    }

    #[test]
    pub fn test_compare_equal() {
        let package1 = Rpm {
            name: "docker-engine".to_string(),
            epoch: 0,
            version: PackageVersion("18.09.0.200".to_string()),
            release: PackageVersion("20.h47.28.15.eulerosv2r10".to_string()),
            arch: "x86_64".to_string(),
            full_name: "docker-engine-18.09.0.200-200.h47.28.15.eulerosv2r10.x86_64".to_string(),
            full_version: "18.09.0.200-200.h47.28.15.eulerosv2r10.x86_64".to_string(),
        };
        let package2 = Rpm {
            name: "docker-engine".to_string(),
            epoch: 1,
            version: PackageVersion("18.09.0".to_string()),
            release: PackageVersion("20.h62.33.19.eulerosv2r10".to_string()),
            arch: "x86_64".to_string(),
            full_name: "docker-engine-1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64".to_string(),
            full_version: "1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64".to_string(),
        };

        assert!(package2 > package1)
    }

    #[test]
    pub fn test_from_name_and_full_version() {
        assert!(Rpm::from_name_and_full_version("", "").is_none());

        let package = Rpm::from_name_and_full_version("cups-libs", "1.6.3-26.h1.x86_64").unwrap();

        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "cups-libs");
        assert_eq!(package.version, PackageVersion("1.6.3".to_string()));
        assert_eq!(package.release, PackageVersion("26.h1".to_string()));
        assert_eq!(package.full_name, "cups-libs-1.6.3-26.h1.x86_64");
    }
}
