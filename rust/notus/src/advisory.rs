use std::collections::HashMap;

use models::{FixedPackage, FixedVersion, Specifier};

use crate::packages::{deb::Deb, ebuild::EBuild, rpm::Rpm, slack::Slack, Package};

pub type Advisories<P> = HashMap<String, Vec<Advisory<P>>>;

pub enum PackageAdvisories {
    Deb(Advisories<Deb>),
    EBuild(Advisories<EBuild>),
    Rpm(Advisories<Rpm>),
    Slack(Advisories<Slack>),
}

impl PackageAdvisories {
    fn fill_advisory_map<P: Package>(
        advisory_map: &mut Advisories<P>,
        advisories: Vec<models::Advisory>,
    ) {
        // Iterate through advisories of parse file
        for advisory in advisories {
            // Iterate through fixed_packages of single advisories
            for fixed_package in advisory.fixed_packages {
                // Create Advisory for fixed package information
                let adv = match Advisory::create(advisory.oid.clone(), &fixed_package) {
                    Some(adv) => adv,
                    None => continue, // TODO: Some handling, at least logging
                };
                // Add advisory to map
                match advisory_map.get_mut(&fixed_package.name) {
                    Some(advisories) => {
                        advisories.push(adv);
                    }
                    None => {
                        advisory_map.insert(fixed_package.name, vec![adv]);
                    }
                };
            }
        }
    }
}

impl From<models::Advisories> for PackageAdvisories {
    fn from(value: models::Advisories) -> Self {
        match value.package_type {
            models::PackageType::DEB => {
                let mut advisory_map: Advisories<Deb> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories);
                Self::Deb(advisory_map)
            }
            models::PackageType::EBUILD => {
                let mut advisory_map: Advisories<EBuild> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories);
                Self::EBuild(advisory_map)
            }
            models::PackageType::RPM => {
                let mut advisory_map: Advisories<Rpm> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories);
                Self::Rpm(advisory_map)
            }
            models::PackageType::SLACK => {
                let mut advisory_map: Advisories<Slack> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories);
                Self::Slack(advisory_map)
            }
        }
    }
}

pub struct Advisory<P>
where
    P: Package,
{
    oid: String,
    package_information: PackageInformation<P>,
}

impl<P> Advisory<P>
where
    P: Package,
{
    pub fn create(oid: String, fixed_package: &FixedPackage) -> Option<Self> {
        match &fixed_package.version {
            // Package information can be either given by full name, name and full version
            // or as a range
            models::VersionEntry::ByFullName { specifier } => {
                // Parse package from full name
                let package = match P::from_full_name(&fixed_package.name) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                // Create Advisory Entry
                Some(Advisory {
                    oid,
                    package_information: PackageInformation::Single {
                        specifier: specifier.clone(),
                        package,
                    },
                })
            }
            models::VersionEntry::ByNameAndFullVersion {
                full_version,
                specifier,
            } => {
                // Parse package from name and full version
                let package = match P::from_name_and_full_version(&fixed_package.name, full_version)
                {
                    Some(pkg) => pkg,
                    None => return None,
                };
                // Create Advisory Entry
                Some(Advisory {
                    oid,
                    package_information: PackageInformation::Single {
                        specifier: specifier.clone(),
                        package,
                    },
                })
            }
            models::VersionEntry::ByRange { range } => {
                // Parse both packages from name and full version
                let start = match P::from_name_and_full_version(&fixed_package.name, &range.start) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                let end = match P::from_name_and_full_version(&fixed_package.name, &range.end) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                // Create Advisory Entry
                Some(Advisory {
                    oid,
                    package_information: PackageInformation::Range { start, end },
                })
            }
        }
    }

    pub fn is_vulnerable(&self, pkg: &P) -> bool {
        match &self.package_information {
            PackageInformation::Single { specifier, package } => match specifier {
                Specifier::GT => pkg <= package,
                Specifier::LT => pkg >= package,
                Specifier::GE => pkg < package,
                Specifier::LE => pkg > package,
                Specifier::EQ => pkg != package,
            },
            PackageInformation::Range { start, end } => pkg >= start && pkg < end,
        }
    }

    pub fn get_oid(&self) -> String {
        self.oid.clone()
    }

    pub fn get_fixed_version(&self) -> FixedVersion {
        match &self.package_information {
            PackageInformation::Single { specifier, package } => FixedVersion::Single {
                version: package.get_version(),
                specifier: specifier.clone(),
            },
            PackageInformation::Range { start, end } => FixedVersion::Range {
                start: start.get_version(),
                end: end.get_version(),
            },
        }
    }
}

pub enum PackageInformation<P>
where
    P: Package,
{
    Single { specifier: Specifier, package: P },
    Range { start: P, end: P },
}
