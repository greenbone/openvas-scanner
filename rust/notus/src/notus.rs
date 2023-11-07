use std::{collections::HashMap, fmt::Display};

use models::{NotusResults, VulnerablePackage};

use crate::{
    advisory::{Advisories, PackageAdvisories},
    loader::AdvisoriesLoader,
    packages::Package,
};

#[derive(PartialEq, PartialOrd, Debug)]

pub enum NotusError {
    InvalidOS,
    JSONParseError,
    UnsupportedVersion(String),
}

impl Display for NotusError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotusError::InvalidOS => todo!(),
            NotusError::JSONParseError => todo!(),
            NotusError::UnsupportedVersion(_) => todo!(),
        }
    }
}

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

    fn load_new_advisories(&self, os: &str) -> Result<PackageAdvisories, NotusError> {
        // TODO: Error handling
        let advisories = self.loader.load_package_advisories(os).unwrap();

        Ok(PackageAdvisories::from(advisories))
    }

    fn parse_and_compare<P: Package>(
        packages: Vec<String>,
        advisories: &Advisories<P>,
    ) -> NotusResults {
        let mut results: NotusResults = HashMap::new();
        for package in packages {
            match P::from_full_name(&package) {
                Some(package) => match advisories.get(&package.get_name()) {
                    Some(advisories) => {
                        for advisory in advisories {
                            if advisory.is_vulnerable(&package) {
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
                },
                // Unable to parse user input
                None => continue, // TODO: Some Error handling, at least Logging
            }
        }

        results
    }

    pub fn scan(&mut self, os: &str, packages: Vec<String>) -> Result<NotusResults, NotusError> {
        // Load advisories if not loaded
        if !self.loaded_advisories.contains_key(&os.to_string()) {
            self.loaded_advisories
                .insert(os.to_string(), self.load_new_advisories(&os)?);
        }
        let advisories = &self.loaded_advisories[&os.to_string()];

        // Parse and compare package list depending on package type of loaded advisories
        let results = match advisories {
            PackageAdvisories::Deb(adv) => Self::parse_and_compare(packages, adv),
            PackageAdvisories::EBuild(adv) => Self::parse_and_compare(packages, adv),
            PackageAdvisories::Rpm(adv) => Self::parse_and_compare(packages, adv),
            PackageAdvisories::Slack(adv) => Self::parse_and_compare(packages, adv),
        };

        Ok(results)
    }
}
