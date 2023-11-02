// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later
use super::PackageVersion;
use regex::RegexBuilder;
use std::{
    cmp::Ordering,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

// Supported packages types.
/// Represent a based Redhat package
#[derive(Debug, Default, Clone)]
pub struct Rpm {
    name: String,
    full_name: String,
    full_version: String,
    epoch: u64,
    version: String,
    release: String,
    arch: String,
}
impl Hash for Rpm {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.full_name.hash(state);
    }
}

static EXCEPTIONS: [&str; 2] = ["_fips", ".ksplice"];

impl Rpm {
    fn new(
        name: String,
        epoch: u64,
        version: String,
        release: String,
        arch: String,
        full_name: String,
        full_version: String,
    ) -> Self {
        Self {
            name,
            full_name,
            full_version,
            epoch,
            version,
            release,
            arch,
        }
    }

    /// Returns a Some<Ordering> struct or None if not comparable
    fn compare(&self, other: &Rpm) -> Option<Ordering> {
        if self.name != other.name {
            return None;
        }
        println!("los nombres son iguales");
        if self.arch != other.arch {
            return None;
        }
        println!("las arch son iguales");
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

        if let Some(comp) =
            PackageVersion::new(&self.version).partial_cmp(&PackageVersion::new(&other.version))
        {
            if comp.is_ne() {
                return Some(comp);
            }
        }

        PackageVersion::new(&self.release).partial_cmp(&PackageVersion::new(&other.release))
    }

    fn hash_calc(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }

    pub fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let full_name = full_name.trim();

        let re = RegexBuilder::new(r"^(.*)-(?:(\d+):)?([^-]+)-([^-]+)\.([^-]+)$")
            .build()
            .unwrap();

        // Get all fields
        let (name, epochstr, version, release, arch) = match re.captures(full_name) {
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
            version: version.to_string(),
            release: release.to_string(),
            arch: arch.to_string(),
        })
    }

    pub fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }

        let name = name.trim();
        let full_version = full_version.trim();

        let re = RegexBuilder::new(r"^(?:(\d+):)?([^-]+)-([^-]+)\.([^-]+)$")
            .build()
            .unwrap();

        // Get all fields
        let (epochstr, version, release, arch) = match re.captures(full_version) {
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
            version: version.to_string(),
            release: release.to_string(),
            arch: arch.to_string(),
        })
    }
}

#[cfg(test)]
mod rpm_tests {
    use crate::packages;

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
        assert_eq!(package.version, "11.2.2");
        assert_eq!(package.release, "2.20160614");
        assert_eq!(package.full_name, "mesa-libgbm-11.2.2-2.20160614.x86_64");

        let package = Rpm::from_full_name("keyutils-1.5.8-3.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "keyutils");
        assert_eq!(package.version, "1.5.8");
        assert_eq!(package.release, "3");
        assert_eq!(package.full_name, "keyutils-1.5.8-3.x86_64");

        let package = Rpm::from_full_name("httpd-manual-2.4.6-45.0.1.4.h10.noarch").unwrap();
        assert_eq!(package.arch, "noarch");
        assert_eq!(package.name, "httpd-manual");
        assert_eq!(package.version, "2.4.6");
        assert_eq!(package.release, "45.0.1.4.h10");
        assert_eq!(package.full_name, "httpd-manual-2.4.6-45.0.1.4.h10.noarch");

        let package = Rpm::from_full_name("cups-libs-1.6.3-26.h1.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "cups-libs");
        assert_eq!(package.version, "1.6.3");
        assert_eq!(package.release, "26.h1");
        assert_eq!(package.full_name, "cups-libs-1.6.3-26.h1.x86_64");

        let package = Rpm::from_full_name("GConf2-3.2.6-8.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "GConf2");
        assert_eq!(package.version, "3.2.6");
        assert_eq!(package.release, "8");
        assert_eq!(package.full_name, "GConf2-3.2.6-8.x86_64");

        let package = Rpm::from_full_name("libtool-ltdl-2.4.2-21.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "libtool-ltdl");
        assert_eq!(package.version, "2.4.2");
        assert_eq!(package.release, "21");
        assert_eq!(package.full_name, "libtool-ltdl-2.4.2-21.x86_64");

        let package = Rpm::from_full_name("microcode_ctl-2.1-22.6.h2.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "microcode_ctl");
        assert_eq!(package.version, "2.1");
        assert_eq!(package.release, "22.6.h2");
        assert_eq!(package.full_name, "microcode_ctl-2.1-22.6.h2.x86_64");

        let package = Rpm::from_full_name("postgresql-libs-9.2.23-3.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "postgresql-libs");
        assert_eq!(package.version, "9.2.23");
        assert_eq!(package.release, "3");
        assert_eq!(package.full_name, "postgresql-libs-9.2.23-3.x86_64");

        let package = Rpm::from_full_name("NetworkManager-1.8.0-9.h2.x86_64").unwrap();
        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "NetworkManager");
        assert_eq!(package.version, "1.8.0");
        assert_eq!(package.release, "9.h2");
        assert_eq!(package.full_name, "NetworkManager-1.8.0-9.h2.x86_64");

        let package = Rpm::from_full_name("perl-Pod-Escapes-1.04-285.h2.noarch").unwrap();
        assert_eq!(package.arch, "noarch");
        assert_eq!(package.name, "perl-Pod-Escapes");
        assert_eq!(package.version, "1.04");
        assert_eq!(package.release, "285.h2");
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
        assert_eq!(package.version, "18.09.0");
        assert_eq!(package.release, "200.h62.33.19.eulerosv2r10");
        assert_eq!(package.arch, "x86_64");
    }

    #[test]
    pub fn test_exceptions() {
        let package1 = Rpm::from_full_name("gnutls-3.6.16-4.el8.x86_64");
        let package2 = Rpm::from_full_name("gnutls-3.6.16-4.0.1.el8_fips.x86_64");

        assert!(package1
            .as_ref()
            .unwrap()
            .compare(package2.as_ref().unwrap())
            .is_none());
        assert!(package2
            .as_ref()
            .unwrap()
            .compare(package1.as_ref().unwrap())
            .is_none());

        let package1 = Rpm::from_full_name("gnutls-3.6.16-4.el8_fips.x86_64");
        assert!(package2
            .as_ref()
            .unwrap()
            .compare(&package1.unwrap())
            .unwrap()
            .is_gt());

        let package1 = Rpm::from_full_name("openssl-libs-1.0.2k-24.0.3.el7_8.x86_64");
        let package2 = Rpm::from_full_name("openssl-libs-1.0.2k-24.0.3.ksplice1.el7_9.x86_64");
        assert!(package1
            .as_ref()
            .unwrap()
            .compare(package2.as_ref().unwrap())
            .is_none());
        assert!(package2
            .as_ref()
            .unwrap()
            .compare(package1.as_ref().unwrap())
            .is_none());

        let package1 = Rpm::from_full_name("openssl-libs-1.0.2k-24.0.3.ksplice1.el7_8.x86_64");
        assert!(package2
            .as_ref()
            .unwrap()
            .compare(&package1.as_ref().unwrap())
            .unwrap()
            .is_gt());
    }

    #[test]
    pub fn test_compare_gt() {
        let package1 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.3-4.x86_64".to_string(),
            "1.2.3-4.x86_64".to_string(),
        );
        let package2 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.4".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.4-4.x86_64".to_string(),
            "1.2.4-4.x86_64".to_string(),
        );
        assert!(package2.compare(&package1).unwrap().is_gt());

        let package2 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "5".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.3-5.x86_64".to_string(),
            "1.2.3-5.x86_64".to_string(),
        );
        assert!(package2.compare(&package1).unwrap().is_gt());
    }

    #[test]
    pub fn test_compare_gt_different_architecture() {
        let package1 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.3-4.x86_64".to_string(),
            "1.2.3-4.x86_64".to_string(),
        );
        let package2 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "4".to_string(),
            "aarch64".to_string(),
            "foo-bar-1.2.3-4.aarch64".to_string(),
            "1.2.3-4.aarch64".to_string(),
        );
        let package3 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.4".to_string(),
            "4".to_string(),
            "aarch64".to_string(),
            "foo-bar-1.2.4-4.aarch64".to_string(),
            "1.2.4-4.aarch64".to_string(),
        );
        let package4 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "5".to_string(),
            "aarch64".to_string(),
            "foo-bar-1.2.3-5.aarch64".to_string(),
            "1.2.3-5.aarch64".to_string(),
        );
        //Not comparable, because different archs. Compare returns None.
        assert!(package2.compare(&package1).is_none());
        assert!(package1.compare(&package2).is_none());
        assert!(package3.compare(&package1).is_none());
        assert!(package1.compare(&package3).is_none());
        assert!(package4.compare(&package1).is_none());
        assert!(package1.compare(&package4).is_none());
    }

    #[test]
    pub fn test_compare_gt_different_epoch() {
        let package1 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.3-4.x86_64".to_string(),
            "1.2.3-4.x86_64".to_string(),
        );
        let package2 = Rpm::new(
            "foo-bar".to_string(),
            1,
            "1.2.3".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.3-4.x86_64".to_string(),
            "1:1.2.3-4.x86_64".to_string(),
        );
        assert!(!package1.compare(&package2).unwrap().is_gt());
        assert!(package2.compare(&package1).unwrap().is_gt());
    }

    #[test]
    pub fn test_compare_gt_different_name() {
        let package1 = Rpm::new(
            "foo".to_string(),
            0,
            "1.2.3".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-1.2.3-4.x86_64".to_string(),
            "1.2.3-4.x86_64".to_string(),
        );
        let package2 = Rpm::new(
            "bar".to_string(),
            0,
            "1.2.3".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "bar-1.2.3-4.x86_64".to_string(),
            "1.2.3-4.x86_64".to_string(),
        );
        assert!(package2.compare(&package1).is_none());
        assert!(package1.compare(&package2).is_none());
    }

    #[test]
    pub fn test_compare_less() {
        let package1 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.3-4.x86_64".to_string(),
            "1.2.3-4.x86_64".to_string(),
        );
        let package2 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.4".to_string(),
            "4".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.4-4.x86_64".to_string(),
            "1.2.4-4.x86_64".to_string(),
        );
        assert!(package1.compare(&package2).unwrap().is_lt());

        let package2 = Rpm::new(
            "foo-bar".to_string(),
            0,
            "1.2.3".to_string(),
            "5".to_string(),
            "x86_64".to_string(),
            "foo-bar-1.2.3-5.x86_64".to_string(),
            "1.2.3-5.x86_64".to_string(),
        );
        assert!(package1.compare(&package2).unwrap().is_lt());
    }

    #[test]
    pub fn test_compare_equal() {
        let package1 = Rpm::new(
            "docker-engine".to_string(),
            0,
            "18.09.0.200".to_string(),
            "20.h47.28.15.eulerosv2r10".to_string(),
            "x86_64".to_string(),
            "docker-engine-18.09.0.200-200.h47.28.15.eulerosv2r10.x86_64".to_string(),
            "18.09.0.200-200.h47.28.15.eulerosv2r10.x86_64".to_string(),
        );
        let package2 = Rpm::new(
            "docker-engine".to_string(),
            1,
            "18.09.0".to_string(),
            "20.h62.33.19.eulerosv2r10".to_string(),
            "x86_64".to_string(),
            "docker-engine-1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64".to_string(),
            "1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64".to_string(),
        );

        assert!(package2.compare(&package1).unwrap().is_gt())
    }

    #[test]
    pub fn test_from_name_and_full_version() {
        assert!(Rpm::from_name_and_full_version("", "").is_none());

        let package = Rpm::from_name_and_full_version("cups-libs", "1.6.3-26.h1.x86_64").unwrap();

        assert_eq!(package.arch, "x86_64");
        assert_eq!(package.name, "cups-libs");
        assert_eq!(package.version, "1.6.3");
        assert_eq!(package.release, "26.h1");
        assert_eq!(package.full_name, "cups-libs-1.6.3-26.h1.x86_64");
    }
}
