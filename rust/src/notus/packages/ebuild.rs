// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{cmp::Ordering, fmt::Display, vec};

use itertools::{EitherOrBoth, Itertools};
use lazy_regex::{Lazy, lazy_regex};
use regex::Regex;

use super::{Package, PackageVersion};

static RE_FULL: Lazy<Regex> = lazy_regex!(
    r"^(?x)
    (?:
        .*
        /
    )?
    (?P<name>
        [[:alnum:]_]
        [[:alnum:]_+-]*
    )
    -
    (?P<version>
        [[:digit:]]+
        (?:
            \.
            [[:digit:]]+
        )*
        [[:alpha:]]?
    )
    (?P<suffix> # will be captured with a leading '_'
        (?:
            _(?:alpha|beta|pre|rc|p)[[:digit:]]*
        )*
    )
    (?:
        -r
        (?P<revision>
            [[:digit:]]+
        )
    )?
    $"
);

static RE_NAME: Lazy<Regex> = lazy_regex!(
    r"^(?x)
    (?:
        .*
        /
    )?
    (?P<name>
        [[:alnum:]_]
        [[:alnum:]_+-]*
    )
    $"
);

static RE_VERSION: Lazy<Regex> = lazy_regex!(
    r"^(?x)
    (?P<version>
        [[:digit:]]+
        (?:
            \.
            [[:digit:]]+
        )*
        [[:alpha:]]?
    )
    (?P<suffix> # will be captured with a leading '_'
        (?:
            _(?:alpha|beta|pre|rc|p)[[:digit:]]*
        )*
    )
    (?:
        -r
        (?P<revision>
            [[:digit:]]+
        )
    )?
    $"
);

#[derive(Debug, PartialEq, Clone)]
enum Suffix {
    Alpha(u64),
    Beta(u64),
    Pre(u64),
    Rc(u64),
    Normal,
    P(u64),
}

impl Default for Suffix {
    fn default() -> Self {
        Suffix::Normal
    }
}

impl From<&Suffix> for (u8, u64) {
    fn from(suffix: &Suffix) -> Self {
        match suffix {
            Suffix::Alpha(n) => (0, *n),
            Suffix::Beta(n) => (1, *n),
            Suffix::Pre(n) => (2, *n),
            Suffix::Rc(n) => (3, *n),
            Suffix::Normal => (4, 0),
            Suffix::P(n) => (5, *n),
        }
    }
}

fn num_to_str(num: u64) -> String {
    if num == 0 {
        String::new()
    } else {
        num.to_string()
    }
}

impl Display for Suffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Suffix::Alpha(n) => write!(f, "alpha{}", num_to_str(*n)),
            Suffix::Beta(n) => write!(f, "beta{}", num_to_str(*n)),
            Suffix::Pre(n) => write!(f, "pre{}", num_to_str(*n)),
            Suffix::Rc(n) => write!(f, "rc{}", num_to_str(*n)),
            Suffix::Normal => Ok(()),
            Suffix::P(n) => write!(f, "p{}", num_to_str(*n)),
        }
    }
}

impl PartialOrd for Suffix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let (release1, num1): (u8, u64) = self.into();
        let (release2, num2): (u8, u64) = other.into();
        release1
            .partial_cmp(&release2)
            .filter(|comp| comp.is_ne())
            .or(num1.partial_cmp(&num2))
    }
}

#[derive(Debug, PartialEq, Clone)]
struct SuffixPart(Vec<Suffix>);

impl Display for SuffixPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return Ok(());
        }
        for suffix in &self.0 {
            write!(f, "_{}", suffix)?;
        }
        Ok(())
    }
}

impl From<&str> for SuffixPart {
    fn from(suffix_full: &str) -> Self {
        if suffix_full.is_empty() {
            return SuffixPart(vec![]);
        }
        let suffix = suffix_full.trim_start_matches('_');
        let mut suffix_part = vec![];
        for suffix in suffix.split('_') {
            if let Some(n) = suffix.strip_prefix("alpha") {
                suffix_part.push(Suffix::Alpha(n.parse::<u64>().unwrap_or_default()));
            } else if let Some(n) = suffix.strip_prefix("beta") {
                suffix_part.push(Suffix::Beta(n.parse::<u64>().unwrap_or_default()));
            } else if let Some(n) = suffix.strip_prefix("pre") {
                suffix_part.push(Suffix::Pre(n.parse::<u64>().unwrap_or_default()));
            } else if let Some(n) = suffix.strip_prefix("rc") {
                suffix_part.push(Suffix::Rc(n.parse::<u64>().unwrap_or_default()));
            } else if let Some(n) = suffix.strip_prefix('p') {
                suffix_part.push(Suffix::P(n.parse::<u64>().unwrap_or_default()));
            } else {
                unreachable!("Invalid suffix matched by regex: {}", suffix_full);
            }
        }
        SuffixPart(suffix_part)
    }
}

impl PartialOrd for SuffixPart {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        for eob in self.0.iter().zip_longest(other.0.iter()) {
            match eob {
                EitherOrBoth::Both(suffix1, suffix2) => {
                    if let Some(ordering) = suffix1.partial_cmp(suffix2) {
                        if ordering.is_ne() {
                            return Some(ordering);
                        }
                    }
                }
                EitherOrBoth::Left(suffix1) => {
                    if let Some(ordering) = suffix1.partial_cmp(&Suffix::Normal) {
                        if ordering.is_ne() {
                            return Some(ordering);
                        }
                    }
                }
                EitherOrBoth::Right(suffix2) => {
                    if let Some(ordering) = Suffix::Normal.partial_cmp(suffix2) {
                        if ordering.is_ne() {
                            return Some(ordering);
                        }
                    }
                }
            }
        }
        Some(Ordering::Equal)
    }
}

/// Represent an ebuild. An ebuild is a bash script which is executed within a special environment. For more information see
/// https://devmanual.gentoo.org/ebuild-writing/file-format/index.html
#[derive(Debug, PartialEq, Clone)]
pub struct EBuild {
    name: String,
    version: PackageVersion,
    suffix_part: SuffixPart,
    revision: u64,
}

impl PartialOrd for EBuild {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.name != other.name {
            return None;
        }

        self.version
            .partial_cmp(&other.version)
            .filter(|comp| comp.is_ne())
            .or(self
                .suffix_part
                .partial_cmp(&other.suffix_part)
                .filter(|comp| comp.is_ne()))
            .or(self.revision.partial_cmp(&other.revision))
    }
}

#[allow(dead_code)]
impl Package for EBuild {
    fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let full_name = full_name.trim();

        // Get all fields
        let (name, version, suffix_part, revision) =
            RE_FULL.captures(full_name).and_then(|caps| {
                let name = caps.name("name")?.as_str();
                let version = caps.name("version")?.as_str();
                let suffix = caps.name("suffix")?.as_str();
                let revision = caps
                    .name("revision")
                    .map(|r| r.as_str().parse::<u64>().unwrap())
                    .unwrap_or_default();

                Some((name.into(), version.into(), suffix.into(), revision))
            })?;

        Some(EBuild {
            name,
            version,
            suffix_part,
            revision,
        })
    }

    fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }
        let name = name.trim();
        let full_version = full_version.trim();

        let name = RE_NAME
            .captures(name)
            .and_then(|caps| caps.name("name").map(|n| n.as_str().into()))?;

        let (version, suffix_part, revision) =
            RE_VERSION.captures(full_version).and_then(|caps| {
                let version = caps.name("version")?.as_str();
                let suffix = caps.name("suffix")?.as_str();
                let revision = caps
                    .name("revision")
                    .map(|r| r.as_str().parse::<u64>().unwrap())
                    .unwrap_or_default();

                Some((version.into(), suffix.into(), revision))
            })?;

        Some(EBuild {
            name,
            version,
            suffix_part,
            revision,
        })
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_version(&self) -> String {
        format!("{}{}-r{}", self.version, self.suffix_part, self.revision)
    }
}

#[cfg(test)]
mod ebuild_tests {
    use std::{
        fs::File,
        io::{self, BufRead},
    };

    use crate::notus::tests::make_test_path;

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
        let path = make_test_path(&["data", "notus", "gentoo_examples.txt"]);
        let file = File::open(path).unwrap();
        for line in io::BufReader::new(file).lines() {
            assert!(EBuild::from_full_name(line.unwrap().as_str()).is_some());
        }
    }

    #[test]
    pub fn test_comparability() {
        let apache1 = EBuild::from_full_name("www-servers/apache-2.4.51-r2").unwrap();
        let apache2 =
            EBuild::from_name_and_full_version("www-servers/apache", "2.4.51-r3").unwrap();

        println!("{}-{}", apache1.get_name(), apache1.get_version());
        println!("{}-{}", apache2.get_name(), apache2.get_version());
        println!("{:?}", apache2.partial_cmp(&apache1));
        assert!(apache2 > apache1);

        let apache3 =
            EBuild::from_name_and_full_version("www-servers/apache", "2.4.51-r3").unwrap();

        assert!(apache2 < apache3);

        let apache4 = EBuild::from_name_and_full_version("apache", "2.4.51-r3").unwrap();
        assert!(apache4 != apache3);
    }
}
