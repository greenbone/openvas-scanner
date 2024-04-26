// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use models::{FixedPackage, FixedVersion, Specifier};

use crate::{
    error::Error,
    packages::{deb::Deb, ebuild::EBuild, rpm::Rpm, slack::Slack, windows::Windows, Package},
};

/// VulnerabilityTests is a collection of Tests to detect vulnerabilities, in case of notus these
/// consist of package names and versions, all corresponding to an OID.
pub type VulnerabilityTests<P> = HashMap<String, Vec<VulnerabilityTest<P>>>;

/// A Product is a collection of Vulnerability tests divided in different Version formats, depending
/// on the underlying packaging system. All supported package systems can be found in this enum.
#[derive(Debug, Clone)]
pub enum Product {
    Deb(VulnerabilityTests<Deb>),
    EBuild(VulnerabilityTests<EBuild>),
    Rpm(VulnerabilityTests<Rpm>),
    Slack(VulnerabilityTests<Slack>),
    Windows(VulnerabilityTests<Windows>),
}

impl Product {
    /// Transform a given list mode VT models into internal representation for performing package
    /// version comparisons.
    fn transform<P: Package>(
        vts_model: Vec<models::VulnerabilityTest>,
    ) -> Result<VulnerabilityTests<P>, Error> {
        let mut vts = VulnerabilityTests::new();
        // Iterate through vulnerability tests of parsed file
        for vt_model in vts_model {
            // Iterate through fixed_packages of single vulnerability test
            for fixed_package in vt_model.fixed_packages {
                // Create Vulnerability Test for fixed package information
                let (pkg_name, adv) =
                    match VulnerabilityTest::create(vt_model.oid.clone(), &fixed_package) {
                        Some(adv) => adv,
                        // Notus data on system are wrong!
                        None => {
                            return Err(Error::VulnerabilityTestParseError(
                                "".to_string(),
                                fixed_package,
                            ))
                        }
                    };
                // Add vulnerability test to map
                match vts.get_mut(&pkg_name) {
                    Some(vts) => {
                        vts.push(adv);
                    }
                    None => {
                        vts.insert(pkg_name, vec![adv]);
                    }
                };
            }
        }

        Ok(vts)
    }
}

impl TryFrom<models::Product> for Product {
    fn try_from(value: models::Product) -> Result<Self, Self::Error> {
        match value.package_type {
            models::PackageType::DEB => {
                let vts = Self::transform(value.vulnerability_tests)?;
                Ok(Self::Deb(vts))
            }
            models::PackageType::EBUILD => {
                let vts = Self::transform(value.vulnerability_tests)?;
                Ok(Self::EBuild(vts))
            }
            models::PackageType::RPM => {
                let vts = Self::transform(value.vulnerability_tests)?;
                Ok(Self::Rpm(vts))
            }
            models::PackageType::SLACK => {
                let vts = Self::transform(value.vulnerability_tests)?;
                Ok(Self::Slack(vts))
            }
            models::PackageType::MSP => {
                let vts = Self::transform(value.vulnerability_tests)?;
                Ok(Self::Windows(vts))
            }
        }
    }

    type Error = Error;
}

/// A Vulnerability Test is a representation of a test to detect a vulnerability in the notus
/// framework. It is associated with an OID and contains package information to detect a
/// vulnerable package. A scan of notus consists of many vulnerability tests for a system based
/// on its installed packages. The OID is used to be able to add additional information to
/// a detected vulnerability afterwards.
#[derive(Debug, Clone)]
pub struct VulnerabilityTest<P>
where
    P: Package,
{
    oid: String,
    package_information: PackageInformation<P>,
}

impl<P> VulnerabilityTest<P>
where
    P: Package,
{
    /// Create a new Vulnerability Test based on a given OID and fixed_package. The fixed_package
    /// is used for comparing an installed package to this vulnerability.
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
                // Create Vulnerability Test Entry
                Some((
                    package.get_name(),
                    VulnerabilityTest {
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
                // Create Vulnerability Test Entry
                Some((
                    package.get_name(),
                    VulnerabilityTest {
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
                // Create Vulnerability Test Entry
                Some((
                    start.get_name(),
                    VulnerabilityTest {
                        oid,
                        package_information: PackageInformation::Range { start, end },
                    },
                ))
            }
        }
    }

    /// Check if a given package is vulnerable.
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

    /// Get the OID of a Vulnerability Test
    pub fn get_oid(&self) -> String {
        self.oid.clone()
    }

    /// Get the fixed version of a Vulnerability Test
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

/// Information for a Package can either be a single version with a comparison specifier or a
/// version range.
#[derive(Debug, Clone)]
pub enum PackageInformation<P>
where
    P: Package,
{
    Single { specifier: Specifier, package: P },
    Range { start: P, end: P },
}
