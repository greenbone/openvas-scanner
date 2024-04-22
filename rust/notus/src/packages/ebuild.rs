// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::cmp::Ordering;

use super::{Package, PackageVersion};

/// Represent a based Ebuild package
#[derive(Debug, PartialEq, Clone)]
pub struct EBuild {
    name: String,
    full_name: String,
    full_version: PackageVersion,
}

impl PartialOrd for EBuild {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.name != other.name {
            return None;
        }

        if self.full_version == other.full_version {
            return Some(Ordering::Equal);
        }

        self.full_version.partial_cmp(&other.full_version)
    }
}

#[allow(dead_code)]
impl Package for EBuild {
    fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let base_name = match full_name.find('/') {
            None => full_name,
            Some(i) => &full_name[i + 1..],
        };
        if base_name.is_empty() {
            return None;
        }

        let d_index = match base_name.find('-') {
            None => base_name.len(),
            Some(i) => i,
        };
        let full_version = base_name[d_index..].to_string();
        if full_version.is_empty() {
            return None;
        }
        let name = full_name[..full_name.len() - full_version.len()].to_string();

        Some(EBuild {
            name,
            full_name: full_name.to_string(),
            full_version: PackageVersion(full_version),
        })
    }

    fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }
        let name = name.trim();
        let full_version = full_version.trim();
        let mut full_name = name.to_owned();
        full_name.push('-');
        full_name.push_str(full_version);

        Some(EBuild {
            name: name.to_string(),
            full_name,
            full_version: PackageVersion(full_version.to_string()),
        })
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_version(&self) -> String {
        self.full_version.0.clone()
    }
}

#[cfg(test)]
mod ebuild_tests {
    use std::{
        fs::File,
        io::{self, BufRead},
        path::PathBuf,
    };

    use super::EBuild;
    use super::Package;

    #[test]
    pub fn test_guard() {
        assert!(EBuild::from_full_name("").is_none());
        assert!(EBuild::from_full_name("www-servers/").is_none());
        assert!(EBuild::from_full_name("www-servers/name").is_none());
        assert!(EBuild::from_name_and_full_version("", "1.2.3").is_none());
        assert!(EBuild::from_name_and_full_version("name", "").is_none());
    }

    #[test]
    pub fn test_parse_fullname() {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("data/gentoo_examples.txt");
        let file = File::open(p).unwrap();
        for line in io::BufReader::new(file).lines() {
            assert!(EBuild::from_full_name(line.unwrap().as_str()).is_some());
        }
    }

    #[test]
    pub fn test_comparability() {
        let apache1 = EBuild::from_full_name("www-servers/apache-2.4.51-r2").unwrap();
        let apache2 =
            EBuild::from_name_and_full_version("www-servers/apache", "2.4.51-r3").unwrap();

        assert!(apache2 > apache1);
        assert!(apache1 <= apache2);

        let apache3 =
            EBuild::from_name_and_full_version("www-servers/apache", "2.4.51-r3").unwrap();

        assert!(apache2 <= apache3);
        assert!(apache2 >= apache3);

        let apache4 = EBuild::from_name_and_full_version("apache", "2.4.51-r3").unwrap();
        assert!(apache4 != apache3);
    }
}
