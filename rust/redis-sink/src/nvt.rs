// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::dberror::RedisSinkResult;
use sink::nvt::{NvtPreference, NvtRef, ACT};
use sink::time::AsUnixTimeStamp;

///Alias for time stamps
type TimeT = i64;

/// Convert an Nvt Timestamp string to a time since epoch.
/// If it fails the conversion, return 0
pub fn parse_nvt_timestamp(str_time: &str) -> TimeT {
    str_time.as_timestamp().unwrap_or_default()
}

#[derive(Clone, Debug)]
/// Structure to hold a NVT
pub struct Nvt {
    oid: String,
    name: String,
    filename: String,
    tag: Vec<(String, String)>,
    dependencies: Vec<String>,
    required_keys: Vec<String>,
    mandatory_keys: Vec<String>,
    excluded_keys: Vec<String>,
    required_ports: Vec<String>,
    required_udp_ports: Vec<String>,
    refs: Vec<NvtRef>,
    prefs: Vec<NvtPreference>,
    category: ACT,
    family: String,
}

impl Default for Nvt {
    fn default() -> Nvt {
        Nvt {
            oid: String::new(),
            name: String::new(),
            filename: String::new(),
            tag: vec![],
            dependencies: vec![],
            required_keys: vec![],
            mandatory_keys: vec![],
            excluded_keys: vec![],
            required_ports: vec![],
            required_udp_ports: vec![],
            refs: vec![],
            prefs: vec![],
            category: ACT::End,
            family: String::new(),
        }
    }
}

impl Nvt {
    /// Nvt constructor
    pub fn new() -> RedisSinkResult<Nvt> {
        Ok(Nvt::default())
    }

    /// Set the NVT OID
    pub fn set_oid(&mut self, oid: String) {
        self.oid = oid;
    }

    /// Set the NVT name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Set the NVT tag
    pub fn set_tag(&mut self, tag: Vec<(String, String)>) {
        self.tag = tag;
    }

    /// Set the NVT dependencies
    pub fn set_dependencies(&mut self, dependencies: Vec<String>) {
        self.dependencies = dependencies;
    }

    /// Set the NVT required keys
    pub fn set_required_keys(&mut self, required_keys: Vec<String>) {
        self.required_keys = required_keys;
    }

    /// Set the NVT mandatory keys
    pub fn set_mandatory_keys(&mut self, mandatory_keys: Vec<String>) {
        self.mandatory_keys = mandatory_keys;
    }

    /// Set the NVT excluded keys
    pub fn set_excluded_keys(&mut self, excluded_keys: Vec<String>) {
        self.excluded_keys = excluded_keys;
    }

    /// Set the NVT required ports
    pub fn set_required_ports(&mut self, required_ports: Vec<String>) {
        self.required_ports = required_ports;
    }

    /// Set the NVT required udp ports
    pub fn set_required_udp_ports(&mut self, required_udp_ports: Vec<String>) {
        self.required_udp_ports = required_udp_ports;
    }

    /// Set the NVT category. Check that category is a valid Category
    pub fn set_category(&mut self, category: ACT) {
        self.category = category;
    }

    /// Set the NVT family
    pub fn set_family(&mut self, family: String) {
        self.family = family;
    }

    /// Add a tag to the NVT tags.
    /// The tag names "severity_date", "last_modification" and
    /// "creation_date" are treated special: The value is expected
    /// to be a timestamp  and it is being converted to seconds
    /// since epoch before added as a tag value.
    /// The tag name "cvss_base" will be ignored and not added.
    pub fn add_tag(&mut self, name: String, value: String) {
        match name.as_str() {
            "last_modification" => {
                self.tag
                    .push((name, parse_nvt_timestamp(&value).to_string()));
            }
            "creation_date" => {
                self.tag
                    .push((name, parse_nvt_timestamp(&value).to_string()));
            }
            "severity_date" => {
                self.tag
                    .push((name, parse_nvt_timestamp(&value).to_string()));
            }
            // cvss_base is just ignored
            "cvss_base" => (),
            _ => {
                self.tag.push((name, value));
            }
        }
    }

    /// Function to add a new preference to the Nvt
    pub fn add_pref(&mut self, pref: NvtPreference) {
        self.prefs.push(pref);
    }

    /// Function to add a new reference to the Nvt
    pub fn add_ref(&mut self, nvtref: NvtRef) {
        self.refs.push(nvtref);
    }

    /// Get the NVT OID
    pub fn oid(&self) -> &str {
        &self.oid
    }

    /// Get the NVT name
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn tag(&self) -> &[(String, String)] {
        &self.tag
    }

    /// Get the NVT dependencies
    pub fn dependencies(&self) -> &Vec<String> {
        &self.dependencies
    }

    /// Get the NVT required keys
    pub fn required_keys(&self) -> &Vec<String> {
        &self.required_keys
    }

    /// Get the NVT mandatory keys
    pub fn mandatory_keys(&self) -> &Vec<String> {
        &self.mandatory_keys
    }

    /// Get the NVT excluded keys
    pub fn excluded_keys(&self) -> &Vec<String> {
        &self.excluded_keys
    }

    /// Get the NVT required ports
    pub fn required_ports(&self) -> &Vec<String> {
        &self.required_ports
    }

    /// Get the NVT required udp ports
    pub fn required_udp_ports(&self) -> &Vec<String> {
        &self.required_udp_ports
    }

    /// Get the NVT category.
    pub fn category(&self) -> i32 {
        self.category as i32
    }

    /// Get the NVT family
    pub fn family(&self) -> &str {
        &self.family
    }

    /// Get References. It returns a tuple of three strings
    /// Each string is a references type, and each string
    /// can contain a list of references of the same type.
    /// The string contains in the following types:
    /// (cve_types, bid_types, other_types)
    /// cve and bid strings are CSC strings containing only
    /// "id, id, ...", while other custom types includes the type
    /// and the string is in the format "type:id, type:id, ..."
    pub fn refs(&self) -> (String, String, String) {
        let (bids, cves, xrefs): (Vec<String>, Vec<String>, Vec<String>) =
            self.refs
                .iter()
                .fold((vec![], vec![], vec![]), |(bids, cves, xrefs), b| {
                    match b.class() {
                        "bid" => {
                            let mut new_bids = bids;
                            new_bids.push(b.id().to_string());
                            (new_bids, cves, xrefs)
                        }
                        "cve" => {
                            let mut new_cves = cves;
                            new_cves.push(b.id().to_string());
                            (bids, new_cves, xrefs)
                        }
                        _ => {
                            let mut new_xref: Vec<String> = xrefs;
                            new_xref.push(format!("{}:{}", b.id(), b.class()));
                            (bids, cves, new_xref)
                        }
                    }
                });

        // Some references include a comma. Therefore the refs separator is ", ".
        // The string ", " is not accepted as reference value, since it will misunderstood
        // as ref separator.

        return (
            cves.iter().as_ref().join(", "),
            bids.iter().as_ref().join(", "),
            xrefs.iter().as_ref().join(", "),
        );
    }

    /// Transforms prefs to string representation {id}:{name}:{id}:{default} so that it can be stored into redis
    pub fn prefs(&self) -> Vec<String> {
        let mut prefs = self.prefs.clone();
        prefs.sort_by(|a, b| b.id.unwrap_or_default().cmp(&a.id.unwrap_or_default()));
        let results: Vec<String> = prefs
            .iter()
            .map(|pref| {
                format!(
                    "{}|||{}|||{}|||{}",
                    pref.id().unwrap_or_default(),
                    pref.name(),
                    pref.class().as_ref(),
                    pref.default()
                )
            })
            .collect();
        results
    }

    pub fn set_filename(&mut self, filename: String) {
        self.filename = filename;
    }

    pub fn filename(&self) -> &str {
        self.filename.as_ref()
    }
}
