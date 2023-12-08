// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;

use models::{FixedPackage, FixedVersion, Specifier};

use crate::{
    error::Error,
    packages::{deb::Deb, ebuild::EBuild, rpm::Rpm, slack::Slack, Package},
};

pub type Advisories<P> = HashMap<String, Vec<Advisory<P>>>;

#[derive(Debug, Clone)]
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
    ) -> Result<(), Error> {
        // Iterate through advisories of parse file
        for advisory in advisories {
            // Iterate through fixed_packages of single advisories
            for fixed_package in advisory.fixed_packages {
                // Create Advisory for fixed package information
                let (pkg_name, adv) = match Advisory::create(advisory.oid.clone(), &fixed_package) {
                    Some(adv) => adv,
                    // Notus data on system are wrong!
                    None => return Err(Error::AdvisoryParseError("".to_string(), fixed_package)),
                };
                // Add advisory to map
                match advisory_map.get_mut(&pkg_name) {
                    Some(advisories) => {
                        advisories.push(adv);
                    }
                    None => {
                        advisory_map.insert(pkg_name, vec![adv]);
                    }
                };
            }
        }

        Ok(())
    }
}

impl TryFrom<models::Advisories> for PackageAdvisories {
    fn try_from(value: models::Advisories) -> Result<Self, Self::Error> {
        match value.package_type {
            models::PackageType::DEB => {
                let mut advisory_map: Advisories<Deb> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories)?;
                Ok(Self::Deb(advisory_map))
            }
            models::PackageType::EBUILD => {
                let mut advisory_map: Advisories<EBuild> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories)?;
                Ok(Self::EBuild(advisory_map))
            }
            models::PackageType::RPM => {
                let mut advisory_map: Advisories<Rpm> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories)?;
                Ok(Self::Rpm(advisory_map))
            }
            models::PackageType::SLACK => {
                let mut advisory_map: Advisories<Slack> = HashMap::new();
                Self::fill_advisory_map(&mut advisory_map, value.advisories)?;
                Ok(Self::Slack(advisory_map))
            }
        }
    }

    type Error = Error;
}

#[derive(Debug, Clone)]
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
    pub fn create(oid: String, fixed_package: &FixedPackage) -> Option<(String, Self)> {
        match &fixed_package {
            // Package information can be either given by full name, name and full version
            // or as a range
            models::FixedPackage::ByFullName {
                specifier,
                full_name,
            } => {
                // Parse package from full name
                let package = match P::from_full_name(full_name) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                // Create Advisory Entry
                Some((
                    package.get_name(),
                    Advisory {
                        oid,
                        package_information: PackageInformation::Single {
                            specifier: specifier.clone(),
                            package,
                        },
                    },
                ))
            }
            models::FixedPackage::ByNameAndFullVersion {
                full_version,
                specifier,
                name,
            } => {
                // Parse package from name and full version
                let package = match P::from_name_and_full_version(name, full_version) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                // Create Advisory Entry
                Some((
                    package.get_name(),
                    Advisory {
                        oid,
                        package_information: PackageInformation::Single {
                            specifier: specifier.clone(),
                            package,
                        },
                    },
                ))
            }
            models::FixedPackage::ByRange { range, name } => {
                // Parse both packages from name and full version
                let start = match P::from_name_and_full_version(name, &range.start) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                let end = match P::from_name_and_full_version(name, &range.end) {
                    Some(pkg) => pkg,
                    None => return None,
                };
                // Create Advisory Entry
                Some((
                    start.get_name(),
                    Advisory {
                        oid,
                        package_information: PackageInformation::Range { start, end },
                    },
                ))
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

#[derive(Debug, Clone)]
pub enum PackageInformation<P>
where
    P: Package,
{
    Single { specifier: Specifier, package: P },
    Range { start: P, end: P },
}
