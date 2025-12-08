// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines an NVT item in storage.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Debug, Display},
};

pub use greenbone_scanner_framework::models::{
    ACT, NvtPreference, NvtRef, TagKey, TagValue, VTData,
};

use crate::notus::advisories::{Vulnerability, VulnerabilityData};

macro_rules! make_nvt_fields {

    ($($doc:expr => $name:ident $( ($($value:ident$(<$st:ident>)?),*) )?),* ) => {
        /// Fields are used to represent a NVT.
        ///
        /// NVTs are complex metadata about a plugin.
        /// This metadata is gathered and stored by a special `description` run parsing through NASL plugins
        /// and executing special `script_*` functions.
        /// While running an interpreter does not have gathered all the data and just starts with a filename
        /// therefore the NVT is split into fields rather than a struct.
        ///
        /// These functions are described in the description crate within builtin crate.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum NvtField {
            $(
             #[doc = $doc]
             $name $( ($( $value$(<$st>)? ),*) )?
             ),*
        }

        /// Key are the keys to get the field defines in NvtField
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum NvtKey {
           $(
             #[doc = $doc]
             $name
           ),*
        }
    };
}

impl NvtField {
    pub fn move_to_data(self, data: &mut VTData) {
        match self {
            NvtField::Oid(oid) => data.oid = oid,
            NvtField::FileName(s) => data.filename = s,

            NvtField::Name(s) => data.name = s,
            NvtField::Tag(key, name) => {
                data.tag.insert(key, name);
            }
            NvtField::Dependencies(s) => data.dependencies.extend(s),
            NvtField::RequiredKeys(s) => data.required_keys.extend(s),
            NvtField::MandatoryKeys(s) => data.mandatory_keys.extend(s),
            NvtField::ExcludedKeys(s) => data.excluded_keys.extend(s),
            NvtField::RequiredPorts(s) => data.required_ports.extend(s),
            NvtField::RequiredUdpPorts(s) => data.required_udp_ports.extend(s),
            NvtField::Preference(s) => data.preferences.push(s),
            NvtField::Reference(s) => data.references.extend(s),
            NvtField::Category(s) => data.category = s,
            NvtField::Family(s) => data.family = s,
        };
    }
}

// "The full NVT" => Nvt(Nvt),
make_nvt_fields! {
   "Is an identifying field" => Oid(String),
    "The filename of the NASL Plugin

The filename is set on a description run and is not read from the NASL script." => FileName(String),

    "Name of a plugin" => Name(String),
    "Tags of a plugin" => Tag(TagKey, TagValue),
        "Dependencies of other scripts that must be run upfront" => Dependencies(Vec<String>),
    r###"Required keys

Those keys must be set to run this script. Otherwise it will be skipped."### =>
    RequiredKeys(Vec<String>),
    r###"Mandatory keys

Those keys must be set to run this script. Otherwise it will be skipped."### =>
    MandatoryKeys(Vec<String>),
    r###"Excluded keys

Those keys must not be set to run this script. Otherwise it will be skipped."### =>
    ExcludedKeys(Vec<String>),
    r###"Required TCP ports

Those ports must be found and open. Otherwise it will be skipped."### =>
    RequiredPorts(Vec<String>),
    r###"Required UDP ports

Those ports must be found and open. Otherwise it will be skipped."### =>
    RequiredUdpPorts(Vec<String>),
    r###"Preferences that can be set by a User"### =>
    Preference(NvtPreference),
    r###"Reference either cve, bid, ..."### =>
    Reference(Vec<NvtRef>),
    r###"Category of a plugin

Category will be used to identify the type of the NASL plugin."### =>
    Category(ACT),
    r###"Family"### =>
    Family(String)
}

#[derive(Clone)]
pub struct Oid(pub String);

#[derive(Clone)]
pub struct FileName(pub String);

#[derive(Clone)]
pub struct FeedVersion;

#[derive(Clone)]
pub struct Feed;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
/// Structure to hold a VT
pub struct Nvt {
    pub data: greenbone_scanner_framework::models::VTData,
}

impl Display for Nvt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.data)
    }
}

impl Nvt {
    /// Returns Err with the feed_version if it is a version Ok otherwise
    /// // TODO: delete
    pub fn set_from_field(&mut self, field: NvtField) {
        field.move_to_data(&mut self.data);
    }
}

impl From<VulnerabilityData> for Nvt {
    fn from(value: VulnerabilityData) -> Self {
        let oid = value.adv.oid.clone();
        let v: Vulnerability = value.into();
        (&oid as &str, v).into()
    }
}

impl From<(&str, Vulnerability)> for Nvt {
    fn from(v: (&str, Vulnerability)) -> Nvt {
        fn tag_to_vec(v: &Vulnerability) -> BTreeMap<TagKey, TagValue> {
            let mut tags: BTreeMap<TagKey, TagValue> = BTreeMap::new();
            if !v.affected.is_empty() {
                tags.insert(TagKey::Affected, TagValue::from(v.affected.as_ref()));
            }
            if !v.summary.is_empty() {
                tags.insert(TagKey::Summary, TagValue::from(v.summary.as_ref()));
            }
            if !v.impact.is_empty() {
                tags.insert(TagKey::Impact, TagValue::from(v.impact.as_ref()));
            }
            if !v.insight.is_empty() {
                tags.insert(TagKey::Insight, TagValue::from(v.insight.as_ref()));
            }
            if !v.solution.is_empty() {
                tags.insert(TagKey::Solution, TagValue::from(v.solution.as_ref()));
            }
            if !v.solution_type.is_empty() {
                tags.insert(
                    TagKey::SolutionType,
                    TagValue::from(v.solution_type.as_ref()),
                );
            }
            if !v.vuldetect.is_empty() {
                tags.insert(TagKey::Vuldetect, TagValue::from(v.vuldetect.as_ref()));
            }
            if !v.qod_type.is_empty() {
                tags.insert(TagKey::QodType, TagValue::from(v.qod_type.as_ref()));
            }
            if !v.severity_vector.is_empty() {
                tags.insert(
                    TagKey::SeverityVector,
                    TagValue::from(v.severity_vector.as_ref()),
                );
            }
            if v.creation_date != 0 {
                tags.insert(TagKey::CreationDate, TagValue::from(v.creation_date as i64));
            }
            if v.last_modification != 0 {
                tags.insert(
                    TagKey::LastModification,
                    TagValue::from(v.last_modification as i64),
                );
            }

            tags
        }
        fn get_refs(references: &HashMap<String, Vec<String>>) -> Vec<NvtRef> {
            let mut refs: Vec<NvtRef> = Vec::new();
            for (reftype, vals) in references {
                let mut t = vals
                    .iter()
                    .map(|r| NvtRef::from((reftype.as_str(), r.as_str())))
                    .collect();
                refs.append(&mut t);
            }
            refs
        }

        let (oid, adv) = v;
        Self {
            data: VTData {
                oid: oid.to_string(),
                name: adv.name.clone(),
                filename: adv.filename.clone(),
                tag: tag_to_vec(&adv),
                dependencies: Vec::new(),
                required_keys: Vec::new(),
                mandatory_keys: Vec::new(),
                excluded_keys: Vec::new(),
                required_ports: Vec::new(),
                required_udp_ports: Vec::new(),
                references: get_refs(&adv.refs),
                preferences: Vec::new(),
                category: ACT::GatherInfo,
                family: adv.family,
            },
        }
    }
}

impl From<NvtField> for Nvt {
    fn from(value: NvtField) -> Self {
        match value {
            NvtField::Oid(oid) => Self {
                data: VTData {
                    oid,
                    ..Default::default()
                },
            },
            NvtField::FileName(filename) => Self {
                data: VTData {
                    filename,
                    ..Default::default()
                },
            },
            NvtField::Name(name) => Self {
                data: VTData {
                    name,
                    ..Default::default()
                },
            },

            NvtField::Tag(key, value) => Self {
                data: VTData {
                    tag: {
                        let mut result = BTreeMap::new();
                        result.insert(key, value);
                        result
                    },
                    ..Default::default()
                },
            },
            NvtField::Dependencies(dependencies) => Self {
                data: VTData {
                    dependencies,
                    ..Default::default()
                },
            },
            NvtField::RequiredKeys(required_keys) => Self {
                data: VTData {
                    required_keys,
                    ..Default::default()
                },
            },
            NvtField::MandatoryKeys(mandatory_keys) => Self {
                data: VTData {
                    mandatory_keys,
                    ..Default::default()
                },
            },
            NvtField::ExcludedKeys(excluded_keys) => Self {
                data: VTData {
                    excluded_keys,
                    ..Default::default()
                },
            },
            NvtField::RequiredPorts(required_ports) => Self {
                data: VTData {
                    required_ports,
                    ..Default::default()
                },
            },
            NvtField::RequiredUdpPorts(required_udp_ports) => Self {
                data: VTData {
                    required_udp_ports,
                    ..Default::default()
                },
            },
            NvtField::Preference(preferences) => Self {
                data: VTData {
                    preferences: vec![preferences],
                    ..Default::default()
                },
            },
            NvtField::Reference(references) => Self {
                data: VTData {
                    references,
                    ..Default::default()
                },
            },
            NvtField::Category(category) => Self {
                data: VTData {
                    category,
                    ..Default::default()
                },
            },
            NvtField::Family(family) => Self {
                data: VTData {
                    family,
                    ..Default::default()
                },
            },
        }
    }
}
