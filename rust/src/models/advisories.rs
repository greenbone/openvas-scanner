// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use serde::Deserialize;

/// Represents an advisory json file for notus product.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProductsAdvisories {
    /// Version of the advisory file
    pub version: String,
    /// SPDX license identifier
    #[serde(rename = "spdx-license-identifier")]
    pub license_identifier: String,
    /// Copyright
    pub copyright: String,
    /// Vulnerability Family
    pub family: String,
    /// List of Advisories
    #[serde(default)]
    pub advisories: Vec<Advisory>,
}

/// Represents an advisory json file for notus product.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Advisory {
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
    /// Advisory contains a CVE that is listed in the catalog of Known Exploited CVEs from CISA
    #[serde(default)]
    pub cisa_kev: bool,
    /// List of cves
    #[serde(default)]
    pub cves: Vec<String>,
    /// Summary
    pub summary: String,
    /// Insight
    #[serde(default)]
    pub insight: String,
    /// Affected
    pub affected: String,
    /// List of xrefs
    #[serde(default)]
    pub xrefs: Vec<String>,
    /// Quality of detection
    pub qod_type: String,
    /// Severity
    pub severity: Severity,
}

/// A single vulnerability from an advisory file to be stored
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone, PartialEq, Eq)]
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
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Severity {
    /// Origin of the severity
    pub origin: String,
    /// severity date
    pub date: u64,
    /// Cvss version v2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_v2: Option<String>,
    /// cvss vector v3
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_v3: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VulnerabilityData {
    pub adv: Advisory,
    pub family: String,
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

        let mut refs = HashMap::new();
        let mut url = data.adv.xrefs.clone();
        url.push(data.adv.advisory_xref.clone());
        if data.adv.cisa_kev {
            refs.insert(
                "CISA".to_string(),
                vec!["Known Exploited Vulnerability (KEV) catalog".to_string()],
            );
            url.push("https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string());
        }
        refs.insert("URL".to_string(), url);

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
            family: data.family,
            name: data.adv.title,
            category: "3".to_string(),
        }
    }
}
