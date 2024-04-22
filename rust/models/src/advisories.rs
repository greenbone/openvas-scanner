// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

/// Represents an advisory json file for notus product.
#[cfg_attr(feature = "serde_support", derive(serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductsAdivisories {
    /// Version of the advisory file
    pub version: String,
    /// SPDX license identifier
    #[cfg_attr(feature = "serde_support", serde(rename = "spdx-license-identifier"))]
    pub license_identifier: String,
    /// Copyright
    pub copyright: String,
    /// Vulnerability Family
    pub family: String,
    /// List of Advisories
    #[cfg_attr(feature = "serde_support", serde(default))]
    pub advisories: Vec<Advisories>,
}

/// Represents an advisory json file for notus product.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]

pub struct Advisories {
    /// The advisory's title.
    pub title: String,
    /// The advisory's ID.
    pub oid: String,
    /// Creation Date
    pub creation_date: u64,
    /// Last modification date
    pub last_modification: u64,
    /// Advisory ID
    pub advisory_id: String,
    /// Advisory xref
    pub advisory_xref: String,
    /// List of cves
    #[cfg_attr(feature = "serde_support", serde(default))]
    pub cves: Vec<String>,
    /// Summary
    pub summary: String,
    /// Insight
    #[cfg_attr(feature = "serde_support", serde(default))]
    pub insight: String,
    /// Affected
    pub affected: String,
    /// Listo of xrefs
    #[cfg_attr(feature = "serde_support", serde(default))]
    pub xrefs: Vec<String>,
    /// Quality of detection
    pub qod_type: String,
    /// Severity
    pub severity: Severity,
}

/// A single vulnerability from an advisory file to be stored
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Vulnerability {
    /// VT Parameters
    pub vt_params: Vec<String>,
    /// Creation Date
    pub creation_date: u64,
    /// Last modification date
    pub last_modification: u64,
    /// Summary
    pub summary: String,
    /// Impact
    pub impact: String,
    /// Affected
    pub affected: String,
    /// Insight
    pub insight: String,
    /// Solution
    pub solution: String,
    /// Solution Type
    pub solution_type: String,
    /// Vuldetect
    pub vuldetect: String,
    /// Quality of detection
    pub qod_type: String,
    /// Severity vector
    pub severity_vector: String,
    /// File name
    pub filename: String,
    /// All references: xrefs, cves, xrefs, advisory xrefs and advisory id.
    pub refs: HashMap<String, Vec<String>>,
    /// Vulnerability Family
    pub family: String,
    /// Title
    pub name: String,
    /// Category
    pub category: String,
}

/// Severity
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Severity {
    /// Origin of the severity
    pub origin: String,
    /// severity date
    pub date: u64,
    /// Cvss version v2
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub cvss_v2: Option<String>,
    /// cvss vector v3
    #[cfg_attr(
        feature = "serde_support",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub cvss_v3: Option<String>,
}

pub struct ProductsAdivisoriesIterator<'a> {
    products_advisories: &'a ProductsAdivisories,
    index: usize,
}

impl<'a> Iterator for ProductsAdivisoriesIterator<'a> {
    type Item = &'a Advisories;

    fn next(&mut self) -> Option<&'a Advisories> {
        if self.index < self.products_advisories.advisories.len() {
            let result = Some(&self.products_advisories.advisories[self.index]);
            self.index += 1;
            result
        } else {
            None
        }
    }
}

impl ProductsAdivisories {
    pub fn iter(&self) -> ProductsAdivisoriesIterator {
        ProductsAdivisoriesIterator {
            products_advisories: self,
            index: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerabilityData {
    pub adv: Advisories,
    pub famile: String,
    pub filename: String,
}

impl From<VulnerabilityData> for Vulnerability {
    fn from(data: VulnerabilityData) -> Self {
        let sv = match data.adv.severity.cvss_v2 {
            Some(cvss) => cvss,
            None => match data.adv.severity.cvss_v3 {
                Some(cvss) => cvss,
                None => "".to_string(),
            },
        };

        let refs = HashMap::new();
        Self {
            vt_params: Vec::new(),
            creation_date: data.adv.creation_date,
            last_modification: data.adv.last_modification,
            summary: data.adv.summary,
            impact: "".to_string(),
            affected: data.adv.affected,
            insight: data.adv.insight,
            solution: "Please install the updated package(s).".to_string(),
            solution_type: "VendorFix".to_string(),
            vuldetect: "Checks if a vulnerable package version is present on the target host."
                .to_string(),
            qod_type: data.adv.qod_type,
            severity_vector: sv,
            filename: data.filename,
            refs,
            family: data.famile,
            name: data.adv.title,
            category: "3".to_string(),
        }
    }
}
