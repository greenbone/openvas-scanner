// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use models::{NotusResults, VulnerablePackage};

use crate::{
    error::Error,
    loader::{FeedStamp, ProductLoader},
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
#[derive(Debug)]
pub struct Notus<L>
where
    L: ProductLoader,
{
    loader: L,
    loaded_products: HashMap<String, (Product, FeedStamp)>,
    signature_check: bool,
}

impl<L> Notus<L>
where
    L: ProductLoader,
{
    /// Create a new Notus instance based on the given loader.
    pub fn new(loader: L, signature_check: bool) -> Self {
        Notus {
            loader,
            loaded_products: Default::default(),
            signature_check,
        }
    }

    fn load_new_product(&self, os: &str) -> Result<(Product, FeedStamp), Error> {
        tracing::debug!(
            root=?self.loader.get_root_dir(),
            "Loading notus product",
        );
        let (product, stamp) = self.loader.load_product(os)?;

        match Product::try_from(product) {
            Ok(adv) => Ok((adv, stamp)),
            Err(Error::VulnerabilityTestParseError(_, pkg)) => {
                Err(Error::VulnerabilityTestParseError(os.to_string(), pkg))
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

    fn compare<P: Package>(packages: &Vec<P>, vts: &VulnerabilityTests<P>) -> NotusResults {
        let mut results: NotusResults = HashMap::new();
        for package in packages {
            match vts.get(&package.get_name()) {
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
        Ok(Self::compare(&packages, vts))
    }

    fn signature_check(&self) -> Result<(), Error> {
        if self.signature_check {
            match self.loader.verify_signature() {
                Ok(_) => tracing::debug!("Signature check succsessful"),
                Err(feed::VerifyError::MissingKeyring) => {
                    tracing::warn!("Signature check enabled but missing keyring");
                    return Err(Error::SignatureCheckError(
                        feed::VerifyError::MissingKeyring,
                    ));
                }
                Err(feed::VerifyError::BadSignature(e)) => {
                    tracing::warn!("{}", e);
                    return Err(Error::SignatureCheckError(feed::VerifyError::BadSignature(
                        e,
                    )));
                }
                Err(e) => {
                    tracing::warn!("Unexpected error during signature verification: {e}");
                    return Err(Error::HashsumLoadError(e));
                }
            }
        }
        Ok(())
    }

    /// Start a scan of a system given its Operating System as a string and a list of installed
    /// packages. The list of installed packages must also contain their versions. On success a list
    /// of vulnerable packages, including their fixed versions is returned.
    pub fn scan(&mut self, os: &str, packages: &[String]) -> Result<NotusResults, Error> {
        // Load product if not loaded
        let product = match self.loaded_products.get(os) {
            Some((adv, stamp)) => {
                if self.loader.has_changed(os, stamp) {
                    self.signature_check()?;
                    self.loaded_products.remove(os);
                    self.loaded_products
                        .insert(os.to_string(), self.load_new_product(os)?);
                    &self.loaded_products[&os.to_string()].0
                } else {
                    adv
                }
            }
            None => {
                self.signature_check()?;
                self.loaded_products
                    .insert(os.to_string(), self.load_new_product(os)?);
                &self.loaded_products[&os.to_string()].0
            }
        };

        // Parse and compare package list depending on package type of loaded product
        let results = match product {
            Product::Deb(adv) => Self::parse_and_compare(packages, adv)?,
            Product::EBuild(adv) => Self::parse_and_compare(packages, adv)?,
            Product::Rpm(adv) => Self::parse_and_compare(packages, adv)?,
            Product::Slack(adv) => Self::parse_and_compare(packages, adv)?,
            Product::Windows(adv) => Self::parse_and_compare(packages, adv)?,
        };

        Ok(results)
    }

    /// Get the list of available products. These are the supported Operating Systems, that can be
    /// used for a `scan`
    pub fn get_available_os(&self) -> Result<Vec<String>, Error> {
        self.signature_check()?;
        self.loader.get_products()
    }
}
