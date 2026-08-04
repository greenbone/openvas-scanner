// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines an NVT item in storage.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Debug, Display},
};

pub use crate::models::{ACT, NvtPreference, NvtRef, TagKey, TagValue, VTData};

use crate::notus::advisories::{Vulnerability, VulnerabilityData};

#[derive(Clone)]
pub struct Oid(pub String);

#[derive(Clone)]
pub struct FileName(pub String);

#[derive(Clone)]
pub struct FeedVersion;

pub struct Feed;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
/// Structure to hold a VT
pub struct Nvt {
    pub data: VTData,
}

impl Display for Nvt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.data)
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
