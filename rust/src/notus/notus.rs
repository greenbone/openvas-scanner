// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use greenbone_scanner_framework::models::{NotusResults, VulnerablePackage};
use tracing::debug;

use super::{
    error::Error,
    loader::ProductLoader,
    packages::Package,
    vts::{Product, VulnerabilityTests},
};

/// Notus is a tool to check for vulnerabilities on you system based on the installed packages.
/// In order for it to work other tools must be used to collect these packages from your system.
/// Additionally a loader must be given, which loads the list of vulnerable packages, including
/// their versions. It is recommended to use a safe loader like the `HashsumFileLoader`, which
/// loads a product file based of a Hashsum file. Look into the `HashsumFileLoader` for more
/// information.
///
/// Notus will cache loaded products to increase speed for repeated scans of the same systems and
/// automatically updates the cache, when the according file changes.
pub struct Notus {
    loader: ProductLoader,
}

impl Notus {
    /// Create a new Notus instance based on the given loader.
    pub fn new(loader: ProductLoader) -> Self {
        Notus { loader }
    }

    fn load_product(&self, os: &str) -> Result<Product, Error> {
        let product = self.loader.load_product(os)?;

        Product::try_from(product).map_err(|e| {
            if let Error::VulnerabilityTestParseError(_, pkg) = e {
                Error::VulnerabilityTestParseError(os.to_string(), pkg)
            } else {
                e
            }
        })
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

    fn compare<P: Package>(packages: &Vec<P>, vts: &VulnerabilityTests<P>) -> NotusResults {
        let mut results: NotusResults = HashMap::new();
        tracing::trace!(vts_keys = ?vts.keys().collect::<Vec<_>>(), packages=?packages.iter().map(|x|x.get_name()).collect::<Vec<_>>());
        for package in packages {
            let pname = package.get_name();
            match vts.get(&pname) {
                Some(vts) => {
                    for vt in vts {
                        if vt.is_vulnerable(package) {
                            let vul_pkg = VulnerablePackage {
                                name: package.get_name(),
                                installed_version: package.get_version(),
                                fixed_version: vt.get_fixed_version(),
                            };
                            match results.get_mut(&vt.get_oid()) {
                                Some(vul_pkgs) => {
                                    vul_pkgs.push(vul_pkg);
                                }
                                None => {
                                    results.insert(vt.get_oid(), vec![vul_pkg]);
                                }
                            }
                        }
                    }
                }
                // No vulnerability test for package
                None => continue,
            }
        }

        results
    }

    fn parse_and_compare<P: Package>(
        packages: &[String],
        vts: &VulnerabilityTests<P>,
    ) -> Result<NotusResults, Error> {
        let packages = Self::parse(packages)?;
        tracing::trace!(
            packages = packages.len(),
            vts = vts.len(),
            "vulnerability loaded."
        );
        Ok(Self::compare(&packages, vts))
    }

    /// Start a scan of a system given its Operating System as a string and a list of installed
    /// packages. The list of installed packages must also contain their versions. On success a list
    /// of vulnerable packages, including their fixed versions is returned.
    pub fn scan(&mut self, os: &str, packages: &[String]) -> Result<NotusResults, Error> {
        let product = self.load_product(os)?;

        tracing::trace!(os, packages = packages.len(), "products known.");

        // Parse and compare package list depending on package type of loaded product
        let results = match &product {
            Product::Deb(adv) => Self::parse_and_compare(packages, adv)?,
            Product::EBuild(adv) => Self::parse_and_compare(packages, adv)?,
            Product::Rpm(adv) => Self::parse_and_compare(packages, adv)?,
            Product::Slack(adv) => Self::parse_and_compare(packages, adv)?,
            Product::Windows(adv) => Self::parse_and_compare(packages, adv)?,
            Product::Alpm(adv) => Self::parse_and_compare(packages, adv)?,
        };

        debug!(os, vulns = results.len(), "Scan completed.");

        Ok(results)
    }

    /// Get the list of available products. These are the supported Operating Systems, that can be
    /// used for a `scan`
    pub fn get_available_os(&self) -> Result<Vec<String>, Error> {
        self.loader.get_products()
    }
}
