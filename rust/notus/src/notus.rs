// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;

use models::{NotusResults, VulnerablePackage};

use crate::{
    advisory::{Advisories, PackageAdvisories},
    error::Error,
    loader::AdvisoriesLoader,
    packages::Package,
};

#[derive(Debug)]
pub struct Notus<L>
where
    L: AdvisoriesLoader,
{
    loader: L,
    loaded_advisories: HashMap<String, PackageAdvisories>,
}

impl<L> Notus<L>
where
    L: AdvisoriesLoader,
{
    pub fn new(loader: L) -> Self {
        Notus {
            loader,
            loaded_advisories: Default::default(),
        }
    }

    fn load_new_advisories(&self, os: &str) -> Result<PackageAdvisories, Error> {
        let advisories = self.loader.load_package_advisories(os)?;

        match PackageAdvisories::try_from(advisories) {
            Ok(adv) => Ok(adv),
            Err(Error::AdvisoryParseError(_, pkg)) => {
                Err(Error::AdvisoryParseError(os.to_string(), pkg))
            }
            Err(err) => Err(err),
        }
    }

    fn parse<P: Package>(packages: &[String]) -> Result<Vec<P>, Error> {
        // Parse all packages
        let mut parsed_packages = vec![];
        for package in packages {
            match P::from_full_name(package) {
                Some(package) => parsed_packages.push(package),
                // Unable to parse user input
                None => return Err(Error::PackageParseError(package.clone())),
            }
        }

        Ok(parsed_packages)
    }

    fn compare<P: Package>(packages: &Vec<P>, advisories: &Advisories<P>) -> NotusResults {
        let mut results: NotusResults = HashMap::new();
        for package in packages {
            match advisories.get(&package.get_name()) {
                Some(advisories) => {
                    for advisory in advisories {
                        if advisory.is_vulnerable(package) {
                            let vul_pkg = VulnerablePackage {
                                name: package.get_name(),
                                installed_version: package.get_version(),
                                fixed_version: advisory.get_fixed_version(),
                            };
                            match results.get_mut(&advisory.get_oid()) {
                                Some(vul_pkgs) => {
                                    vul_pkgs.push(vul_pkg);
                                }
                                None => {
                                    results.insert(advisory.get_oid(), vec![vul_pkg]);
                                }
                            }
                        }
                    }
                }
                // No advisory for package
                None => continue,
            }
        }

        results
    }

    fn parse_and_compare<P: Package>(
        packages: &[String],
        advisories: &Advisories<P>,
    ) -> Result<NotusResults, Error> {
        let packages = Self::parse(packages)?;
        Ok(Self::compare(&packages, advisories))
    }

    pub fn scan(&mut self, os: &str, packages: &[String]) -> Result<NotusResults, Error> {
        // Load advisories if not loaded
        let advisories = match self.loaded_advisories.get(os) {
            Some(adv) => adv,
            None => {
                self.loaded_advisories
                    .insert(os.to_string(), self.load_new_advisories(os)?);
                &self.loaded_advisories[&os.to_string()]
            }
        };

        // Parse and compare package list depending on package type of loaded advisories
        let results = match advisories {
            PackageAdvisories::Deb(adv) => Self::parse_and_compare(packages, adv)?,
            PackageAdvisories::EBuild(adv) => Self::parse_and_compare(packages, adv)?,
            PackageAdvisories::Rpm(adv) => Self::parse_and_compare(packages, adv)?,
            PackageAdvisories::Slack(adv) => Self::parse_and_compare(packages, adv)?,
        };

        Ok(results)
    }

    pub fn get_available_os(&self) -> Result<Vec<String>, Error> {
        self.loader.get_available_os()
    }
}
