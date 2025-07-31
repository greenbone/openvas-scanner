// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{cmp::Ordering, fmt::Display, iter, vec};

use lazy_regex::{Lazy, lazy_regex};
use regex::Regex;

use super::{Package, PackageVersion};

static RE_FULL: Lazy<Regex> = lazy_regex!(
    r"^(?x)
    (?P<path>
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
    (?P<path>
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

#[derive(Debug, PartialEq, Clone, PartialOrd)]
enum Suffix {
    Alpha(u64),
    Beta(u64),
    Pre(u64),
    Rc(u64),
    Normal,
    P(u64),
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

#[derive(Debug, PartialEq, Clone)]
struct SuffixPart(Vec<Suffix>);

impl Display for SuffixPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return Ok(());
        }
        for suffix in &self.0 {
            write!(f, "_{suffix}")?;
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
        let len = self.0.len().max(other.0.len());
        let it1 = self.0.iter().chain(iter::repeat(&Suffix::Normal)).take(len);
        let it2 = other
            .0
            .iter()
            .chain(iter::repeat(&Suffix::Normal))
            .take(len);
        it1.partial_cmp(it2)
    }
}

/// Represent an ebuild. An ebuild is a bash script which is executed within a special environment. For more information see
/// https://devmanual.gentoo.org/ebuild-writing/file-format/index.html
#[derive(Debug, PartialEq, Clone)]
pub struct EBuild {
    path: String,
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

        (&self.version, &self.suffix_part, &self.revision).partial_cmp(&(
            &other.version,
            &other.suffix_part,
            &other.revision,
        ))
    }
}

#[allow(dead_code)]
impl Package for EBuild {
    fn from_full_name(full_name: &str) -> Option<Self> {
        if full_name.is_empty() {
            return None;
        }
        let full_name = full_name.trim();

        RE_FULL.captures(full_name).and_then(|caps| {
            let path = caps.name("path").map(|m| m.as_str()).unwrap_or_default();
            let name = caps.name("name")?.as_str();
            let version = caps.name("version")?.as_str();
            let suffix = caps.name("suffix")?.as_str();
            let revision = caps
                .name("revision")
                .map(|r| r.as_str().parse::<u64>().unwrap())
                .unwrap_or_default();
            Some(EBuild {
                path: path.into(),
                name: name.into(),
                version: version.into(),
                suffix_part: suffix.into(),
                revision,
            })
        })
    }

    fn from_name_and_full_version(name: &str, full_version: &str) -> Option<Self> {
        if name.is_empty() || full_version.is_empty() {
            return None;
        }
        let name = name.trim();
        let full_version = full_version.trim();

        let (path, name) = RE_NAME.captures(name).and_then(|caps| {
            let path = caps.name("path").map(|m| m.as_str()).unwrap_or_default();
            let name = caps.name("name")?.as_str();
            Some((path.into(), name.into()))
        })?;

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
            path,
            name,
            version,
            suffix_part,
            revision,
        })
    }

    fn get_name(&self) -> String {
        self.path.clone() + &self.name
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

    use crate::notus::{
        packages::{PackageVersion, ebuild::Suffix},
        tests::make_test_path,
    };

    use super::EBuild;
    use super::Package;

    #[test]
    fn test_guard() {
        assert!(EBuild::from_full_name("").is_none());
        assert!(EBuild::from_full_name("www-servers/").is_none());
        assert!(EBuild::from_full_name("www-servers/name").is_none());
        assert!(EBuild::from_name_and_full_version("", "1.2.3").is_none());
        assert!(EBuild::from_name_and_full_version("name", "").is_none());
    }

    #[test]
    fn test_parse_fullname() {
        let ebuild = EBuild::from_full_name(
            "app-i18n/tagainijisho-1.2.0_pre20200118132551_p20201001_p20201001-r42",
        )
        .unwrap();

        assert_eq!(ebuild.path, "app-i18n/");
        assert_eq!(ebuild.name, "tagainijisho");
        assert_eq!(ebuild.version, PackageVersion("1.2.0".to_string()));
        assert_eq!(ebuild.suffix_part.0.len(), 3);
        assert_eq!(ebuild.suffix_part.0[0], Suffix::Pre(20200118132551));
        assert_eq!(ebuild.suffix_part.0[1], Suffix::P(20201001));
        assert_eq!(ebuild.suffix_part.0[2], Suffix::P(20201001));
        assert_eq!(ebuild.revision, 42);
        assert_eq!(ebuild.get_name(), "app-i18n/tagainijisho");
        assert_eq!(
            ebuild.get_version(),
            "1.2.0_pre20200118132551_p20201001_p20201001-r42"
        );

        let ebuild = EBuild::from_full_name("some/path/www-servers/apache-2.4.51-r2").unwrap();
        assert_eq!(ebuild.path, "some/path/www-servers/");
        assert_eq!(ebuild.name, "apache");
        assert_eq!(ebuild.version, PackageVersion("2.4.51".to_string()));
        assert_eq!(ebuild.suffix_part.0.len(), 0);
        assert_eq!(ebuild.revision, 2);
        assert_eq!(ebuild.get_name(), "some/path/www-servers/apache");
        assert_eq!(ebuild.get_version(), "2.4.51-r2");
    }

    #[test]
    fn test_parse_fullname_from_file() {
        let path = make_test_path(&["data", "notus", "gentoo_examples.txt"]);
        let file = File::open(path).unwrap();
        for line in io::BufReader::new(file).lines() {
            assert!(EBuild::from_full_name(line.unwrap().as_str()).is_some());
        }
    }

    #[test]
    fn test_comparability() {
        let apache1 = EBuild::from_full_name("www-servers/apache-2.4.51-r2").unwrap();
        let apache2 =
            EBuild::from_name_and_full_version("www-servers/apache", "2.4.51-r3").unwrap();

        assert!(apache2 > apache1);

        let apache3 =
            EBuild::from_name_and_full_version("www-servers/apache", "2.4.51-r3").unwrap();

        assert!(apache2 == apache3);

        let apache4 = EBuild::from_name_and_full_version("apachee", "2.4.51-r3").unwrap();
        assert!(apache4 != apache3);

        let ebuild1 = EBuild::from_full_name(
            "app-i18n/tagainijisho-1.2.0_pre20200118132551_p20201001_p20201001-r42",
        )
        .unwrap();

        let ebuild2 = EBuild::from_full_name(
            "app-i18n/tagainijisho-1.2.1_pre20200118132551_p20201001_p20201001-r42",
        )
        .unwrap();
        assert!(ebuild1 < ebuild2);

        let ebuild2 = EBuild::from_full_name(
            "app-i18n/tagainijisho-1.2.0_pre20200118132551_p20201001_p20201000-r42",
        )
        .unwrap();
        assert!(ebuild1 > ebuild2);

        let ebuild2 = EBuild::from_full_name(
            "app-i18n/tagainijisho-1.2.0_beta13_pre20200118132551_p20201001_p20201001-r42",
        )
        .unwrap();
        assert!(ebuild1 > ebuild2);
    }
}
