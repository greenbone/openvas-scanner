// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines an item in storage. Currently support Kb items, Nvts in the cache, and notus advisories in the cache
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    str::FromStr,
    sync::{Arc, Mutex},
};

use crate::models::{self, Vulnerability, VulnerabilityData};

use crate::storage::{
    time::AsUnixTimeStamp, types, ContextKey, Dispatcher, Field, Kb, NotusAdvisory, Remover,
    Retriever, StorageError,
};

use super::{FieldKeyResult, Retrieve};

/// Attack Category either set by script_category
///
/// It defines what kind of attack script the nasl plugin is.
/// Some scripts like
///
/// - Init
/// - Scanner
/// - Settings
/// - GatherInfo
///
/// are running before the actual attack scans
///
/// - Attack
/// - MixedAttack
/// - DestructiveAttack
/// - Denial
/// - KillHost
/// - Flood
///
/// are running before cleanup scripts
///
/// - End
///
/// It is defined as a numeric value instead of string representations due to downwards compatible reasons.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Default, Hash)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum ACT {
    /// Defines a initializer
    Init,
    /// Defines a port scanner
    Scanner,
    /// Defines a settings configurator
    Settings,
    /// Gathers information about the environment the scan runs in
    GatherInfo,
    /// Executes actual attacks
    Attack,
    /// Same as attack left for downwards Compatibility
    MixedAttack,
    /// Exhausting attack should not be considered safe to execute
    DestructiveAttack,
    /// Exhausting attack should not be considered safe to execute
    Denial,
    /// Exhausting attack should not be considered safe to execute
    KillHost,
    /// Exhausting attack should not be considered safe to execute
    Flood,
    /// Should be executed at the end
    #[default]
    End,
}

// TODO generalize and use name rather than number
impl FromStr for ACT {
    type Err = StorageError;

    // Is defined as a numeric value instead of string representations due to downwards compatible reasons.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "0" => ACT::Init,
            "1" => ACT::Scanner,
            "2" => ACT::Settings,
            "3" => ACT::GatherInfo,
            "4" => ACT::Attack,
            "5" => ACT::MixedAttack,
            "6" => ACT::DestructiveAttack,
            "7" => ACT::Denial,
            "8" => ACT::KillHost,
            "9" => ACT::Flood,
            "10" => ACT::End,
            _ => return Err(StorageError::UnexpectedData(s.to_owned())),
        })
    }
}

macro_rules! make_str_lookup_enum {
    ($enum_name:ident: $doc:expr => { $($matcher:ident => $key:ident),+ }) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Ord,PartialOrd, Hash)]
        #[cfg_attr(feature = "serde_support",
                   derive(serde::Serialize, serde::Deserialize),
                   serde(rename_all = "snake_case")
        )]
        pub enum $enum_name {
            $(
             #[doc = concat!(stringify!($matcher))]
             $key,
            )*
        }

        impl FromStr for $enum_name {
            type Err = StorageError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use $enum_name::*;
                match s {
                    $(
                    stringify!($matcher) => Ok($key),
                    )*
                    _ => Err(StorageError::UnexpectedData(format!("{}: {}", stringify!($enum_name), s.to_owned()))),
                }
            }
        }

        impl AsRef<str> for $enum_name{
            fn as_ref(&self) -> &str {
                use $enum_name::*;
                match self {
                    $(
                    $key => stringify!($matcher),
                    )*

                }
            }
        }
    };
}

impl Display for TagKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

make_str_lookup_enum! {
    TagKey: "Allowed keys for a tag" => {
        affected => Affected,
        creation_date => CreationDate,
        cvss_base => CvssBase,
        cvss_base_vector => CvssBaseVector,
        deprecated => Deprecated,
        impact => Impact,
        insight => Insight,
        last_modification => LastModification,
        qod => Qod,
        qod_type => QodType,
        severity_date => SeverityDate,
        severity_origin => SeverityOrigin,
        severity_vector => SeverityVector,
        solution => Solution,
        solution_method => SolutionMethod, // legacy can probably removed in the next feed
        solution_type => SolutionType,
        summary => Summary,
        vuldetect => Vuldetect
    }
}

make_str_lookup_enum! {
    SolutionType: "SolutionType is set via script_tag 'solution_type' and allows only the defined values" => {
        Mitigation => Mitigation,
        NoneAvailable => NoneAvailable,
        VendorFix => VendorFix,
        WillNotFix => WillNotFix,
        Workaround => Workaround
    }
}

make_str_lookup_enum! {
    QodType: "QODType is set via script_tag 'qod_type' and allows only the defined values" => {
        executable_version => ExecutableVersion,
        executable_version_unreliable => ExecutableVersionUnreliable,
        exploit => Exploit,
        general_note => GeneralNote,
        package => Package,
        registry => Registry,
        remote_active => RemoteActive,
        remote_analysis => RemoteAnalysis,
        remote_app => RemoteApp,
        remote_banner => RemoteBanner,
        remote_banner_unreliable => RemoteBannerUnreliable,
        remote_probe => RemoteProbe,
        remote_vul => RemoteVul,
        package_unreliable => PackageUnreliable,
        default => Default
    }
}

make_str_lookup_enum! {
    PreferenceType: "Allowed types for preferences" => {
       checkbox => CheckBox,
       entry => Entry,
       file => File,
       password => Password,
       radio => Radio,
       sshlogin => SshLogin,
       integer => Integer
    }
}

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
        pub enum NVTField {
            $(
             #[doc = $doc]
             $name $( ($( $value$(<$st>)? ),*) )?
             ),*
        }

        /// Key are the keys to get the field defines in NVTField
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum NVTKey {
           $(
             #[doc = $doc]
             $name
           ),*
        }
    };
}

// "The full NVT" => Nvt(Nvt),
make_nvt_fields! {
   "Is an identifying field" => Oid(String),
    "The filename of the NASL Plugin

The filename is set on a description run and is not read from the NASL script." => FileName(String),
    "The version of the NASL feed

The version is read from plugins_version.inc." => Version(String),
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
    Family(String),
   "Get complete NVTs" => Nvt(Nvt),
    r###"For deprecated functions"### =>
    NoOp
}

/// Preferences that can be set by a user when running a script.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub struct NvtPreference {
    /// Preference ID
    pub id: Option<i32>,
    /// Preference type
    pub class: PreferenceType,
    /// Name of the preference
    pub name: String,
    /// Default value of the preference
    pub default: String,
}

/// References defines where the information for that vulnerability attack is from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub struct NvtRef {
    /// Reference type ("cve", "bid", ...)
    pub class: String,
    /// Actual reference ID ("CVE-2018-1234", etc)
    pub id: String,
}

impl From<(&str, &str)> for NvtRef {
    fn from(value: (&str, &str)) -> Self {
        let (class, id) = value;
        Self {
            class: class.to_owned(),
            id: id.to_owned(),
        }
    }
}

impl From<(&str, String)> for NvtRef {
    fn from(value: (&str, String)) -> Self {
        let (class, id) = value;
        Self {
            class: class.to_owned(),
            id,
        }
    }
}
impl NvtRef {
    /// Returns class
    pub fn class(&self) -> &str {
        self.class.as_ref()
    }

    /// Returns id
    pub fn id(&self) -> &str {
        self.id.as_ref()
    }
}

impl NvtPreference {
    /// Returns id
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    /// Returns class
    pub fn class(&self) -> PreferenceType {
        self.class
    }

    /// Returns name
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns default
    pub fn default(&self) -> &str {
        self.default.as_ref()
    }
}

impl From<(&str, &str, &str, &str)> for NvtPreference {
    fn from(value: (&str, &str, &str, &str)) -> Self {
        let (id, name, class, default) = value;
        Self {
            id: Some(i32::from_str(id).expect("Invalid Preference ID {id}")),
            class: PreferenceType::from_str(class).expect("Invalid Preference type"),
            name: name.to_owned(),
            default: default.to_owned(),
        }
    }
}
impl From<&NvtPreference> for (String, String, String, String) {
    fn from(pref: &NvtPreference) -> Self {
        let id = pref.id().unwrap().to_string();
        let class = match pref.class {
            PreferenceType::CheckBox => "checkbox",
            PreferenceType::Entry => "entry",
            PreferenceType::File => "file",
            PreferenceType::Password => "password",
            PreferenceType::Radio => "radio",
            PreferenceType::SshLogin => "sshlogin",
            PreferenceType::Integer => "integer",
        };
        let name = pref.name().to_string();
        let def = pref.default().to_string();
        (id, class.to_string(), name, def)
    }
}

impl From<QodType> for i64 {
    fn from(v: QodType) -> Self {
        match v {
            QodType::Exploit => 100,
            QodType::RemoteVul => 99,
            QodType::RemoteApp => 98,
            QodType::Package => 97,
            QodType::Registry => 97,
            QodType::RemoteActive => 95,
            QodType::RemoteBanner => 80,
            QodType::ExecutableVersion => 80,
            QodType::RemoteAnalysis => 70,
            QodType::RemoteProbe => 50,
            QodType::PackageUnreliable => 30,
            QodType::RemoteBannerUnreliable => 30,
            QodType::ExecutableVersionUnreliable => 30,
            QodType::GeneralNote => 1,
            QodType::Default => 70,
        }
    }
}

/// TagValue is a type containing value types of script_tag
pub type TagValue = types::Primitive;

impl TagValue {
    /// Parse the given Value based on the key to TagValue
    // TODO move naslvalue out of syntax to own crate so we can use it here
    pub fn parse<V: ToString>(key: TagKey, value: V) -> Result<Self, StorageError> {
        let error = || StorageError::UnexpectedData(format!("{key:?} => {}", value.to_string()));
        match key {
            TagKey::CreationDate | TagKey::LastModification | TagKey::SeverityDate => value
                .to_string()
                .as_timestamp()
                .ok_or_else(error)
                .map(Self::from),
            // is set to be ignored
            TagKey::CvssBase => Ok(TagValue::Null),
            TagKey::Deprecated => match value.to_string().as_str() {
                "TRUE" | "true" | "1" => Ok(TagValue::Boolean(true)),
                "FALSE" | "false" | "0" => Ok(TagValue::Boolean(false)),
                _ => Err(error()),
            },
            TagKey::SolutionType => SolutionType::from_str(value.to_string().as_str())
                .map(|x| TagValue::String(x.as_ref().to_owned())),
            TagKey::QodType => QodType::from_str(value.to_string().as_str())
                .map(|x| TagValue::String(x.as_ref().to_owned())),
            TagKey::Qod => value
                .to_string()
                .as_str()
                .parse::<i64>()
                .map(Self::from)
                .map_err(|_| error()),
            _ => Ok(Self::from(value.to_string())),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
/// Structure to hold a NVT
pub struct Nvt {
    /// The ID of the nvt.
    pub oid: String,
    /// The name of the nvt.
    pub name: String,
    /// The filename of the nvt.
    pub filename: String,
    /// The tags of the nvt.
    pub tag: BTreeMap<TagKey, TagValue>,
    /// The direct dependencies of the nvt.
    pub dependencies: Vec<String>,
    /// The required keys to run the NVT.
    pub required_keys: Vec<String>,
    /// The Mandatory keys to run the NVT.
    pub mandatory_keys: Vec<String>,
    /// The keys to prevent to run the NVT.
    pub excluded_keys: Vec<String>,
    /// The verified ports necessary to run the NVT.
    pub required_ports: Vec<String>,
    /// The verified ports necessary to run the NVT.
    pub required_udp_ports: Vec<String>,
    /// References
    pub references: Vec<NvtRef>,
    /// Preferences
    pub preferences: Vec<NvtPreference>,
    /// Category
    pub category: ACT,
    /// Family
    pub family: String,
}

impl Display for Nvt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VT {} ({})", self.oid, self.filename)
    }
}

impl Nvt {
    /// Returns Err with the feed_version if it is a version Ok otherwise
    pub fn set_from_field(&mut self, field: NVTField) -> Result<(), String> {
        match field {
            NVTField::Oid(oid) => self.oid = oid,
            NVTField::FileName(s) => self.filename = s,
            NVTField::Version(s) => {
                return Err(s);
            }
            NVTField::Name(s) => self.name = s,
            NVTField::Tag(key, name) => {
                self.tag.insert(key, name);
            }
            NVTField::Dependencies(s) => self.dependencies.extend(s),
            NVTField::RequiredKeys(s) => self.required_keys.extend(s),
            NVTField::MandatoryKeys(s) => self.mandatory_keys.extend(s),
            NVTField::ExcludedKeys(s) => self.excluded_keys.extend(s),
            NVTField::RequiredPorts(s) => self.required_ports.extend(s),
            NVTField::RequiredUdpPorts(s) => self.required_udp_ports.extend(s),
            NVTField::Preference(s) => self.preferences.push(s),
            NVTField::Reference(s) => self.references.extend(s),
            NVTField::Category(s) => self.category = s,
            NVTField::Family(s) => self.family = s,
            NVTField::NoOp => {}
            NVTField::Nvt(x) => *self = x,
        };
        Ok(())
    }
    /// Verifies if a nvt is matching a field
    pub fn matches_field(&self, field: &Field) -> bool {
        match field {
            Field::NVT(nvt_field) => match nvt_field {
                NVTField::Oid(x) => &self.oid == x,
                NVTField::FileName(x) => &self.filename == x,
                NVTField::Name(x) => &self.name == x,
                NVTField::Tag(a, _) => self.tag.contains_key(a),
                NVTField::Dependencies(x) => &self.dependencies == x,
                NVTField::RequiredKeys(x) => &self.required_keys == x,
                NVTField::MandatoryKeys(x) => &self.mandatory_keys == x,
                NVTField::ExcludedKeys(x) => &self.excluded_keys == x,
                NVTField::RequiredPorts(x) => &self.required_ports == x,
                NVTField::RequiredUdpPorts(x) => &self.required_udp_ports == x,
                NVTField::Preference(x) => self.preferences.contains(x),
                NVTField::Reference(x) => &self.references == x,
                NVTField::Category(x) => &self.category == x,
                NVTField::Family(x) => &self.family == x,
                NVTField::Nvt(x) => self == x,
                NVTField::NoOp | NVTField::Version(_) => false,
            },
            Field::KB(_) | Field::NotusAdvisory(_) | Field::Result(_) => false,
        }
    }
    /// Verifies if a nvt is matching a field
    pub fn matches_any_field(&self, field: &[Field]) -> bool {
        field.iter().any(|x| self.matches_field(x))
    }

    /// Transform Self to NVTFields based on a given NVTKey.
    ///
    /// This helper is useful when a caller doesn't want to have the whole VT but just parts from
    /// it.
    pub(crate) fn key_as_field(&self, x: NVTKey) -> Vec<NVTField> {
        match x {
            NVTKey::Oid => {
                if self.oid.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::Oid(self.oid.clone())]
                }
            }
            NVTKey::FileName => {
                if self.filename.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::FileName(self.filename.clone())]
                }
            }
            NVTKey::Version => vec![],
            NVTKey::Name => {
                if self.name.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::Name(self.name.clone())]
                }
            }
            NVTKey::Tag => {
                if self.tag.is_empty() {
                    vec![]
                } else {
                    todo!("doing it last because it is the reason that we have to return a vec")
                }
            }
            NVTKey::Dependencies => {
                if self.dependencies.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::Dependencies(self.dependencies.clone())]
                }
            }
            NVTKey::RequiredKeys => {
                if self.required_keys.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::RequiredKeys(self.required_keys.clone())]
                }
            }
            NVTKey::MandatoryKeys => {
                if self.mandatory_keys.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::MandatoryKeys(self.mandatory_keys.clone())]
                }
            }
            NVTKey::ExcludedKeys => {
                if self.excluded_keys.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::ExcludedKeys(self.excluded_keys.clone())]
                }
            }
            NVTKey::RequiredPorts => {
                if self.required_ports.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::RequiredPorts(self.required_ports.clone())]
                }
            }
            NVTKey::RequiredUdpPorts => {
                if self.required_udp_ports.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::RequiredUdpPorts(self.required_udp_ports.clone())]
                }
            }
            NVTKey::Preference => {
                if self.preferences.is_empty() {
                    vec![]
                } else {
                    self.preferences
                        .clone()
                        .into_iter()
                        .map(NVTField::Preference)
                        .collect()
                }
            }
            NVTKey::Reference => {
                if self.references.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::Reference(self.references.clone())]
                }
            }
            NVTKey::Category => vec![NVTField::Category(self.category)],
            NVTKey::Family => {
                if self.family.is_empty() {
                    vec![]
                } else {
                    vec![NVTField::Family(self.family.clone())]
                }
            }
            NVTKey::Nvt => vec![NVTField::Nvt(self.clone())],
            NVTKey::NoOp => vec![],
        }
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
        }
    }
}

impl From<NVTField> for Nvt {
    fn from(value: NVTField) -> Self {
        match value {
            NVTField::Oid(oid) => Self {
                oid,
                ..Default::default()
            },
            NVTField::FileName(filename) => Self {
                filename,
                ..Default::default()
            },
            NVTField::Version(_) => Default::default(),
            NVTField::Name(name) => Self {
                name,
                ..Default::default()
            },
            NVTField::Tag(key, value) => Self {
                tag: {
                    let mut result = BTreeMap::new();
                    result.insert(key, value);
                    result
                },
                ..Default::default()
            },
            NVTField::Dependencies(dependencies) => Self {
                dependencies,
                ..Default::default()
            },
            NVTField::RequiredKeys(required_keys) => Self {
                required_keys,
                ..Default::default()
            },
            NVTField::MandatoryKeys(mandatory_keys) => Self {
                mandatory_keys,
                ..Default::default()
            },
            NVTField::ExcludedKeys(excluded_keys) => Self {
                excluded_keys,
                ..Default::default()
            },
            NVTField::RequiredPorts(required_ports) => Self {
                required_ports,
                ..Default::default()
            },
            NVTField::RequiredUdpPorts(required_udp_ports) => Self {
                required_udp_ports,
                ..Default::default()
            },
            NVTField::Preference(preferences) => Self {
                preferences: vec![preferences],
                ..Default::default()
            },
            NVTField::Reference(references) => Self {
                references,
                ..Default::default()
            },
            NVTField::Category(category) => Self {
                category,
                ..Default::default()
            },
            NVTField::Family(family) => Self {
                family,
                ..Default::default()
            },
            NVTField::Nvt(nvt) => nvt,
            NVTField::NoOp => Nvt::default(),
        }
    }
}
/// Is a specialized Dispatcher for NVT information within the description block.
pub trait ItemDispatcher {
    /// Dispatches the feed version as well as NVT.
    ///
    /// The NVT is collected when a description run is finished.
    fn dispatch_nvt(&self, nvt: Nvt) -> Result<(), StorageError>;
    /// Dispatches the feed_version.
    ///
    /// Feed version is usually read once.
    fn dispatch_feed_version(&self, version: String) -> Result<(), StorageError>;
    /// Dispatches a knowledge base item.
    ///
    /// Usually the ItemDispatcher is used on description = 1 runs were no KB item should occur. But
    /// to have the possibility to have shared run this interface should allow to handle it
    /// accordingly.
    /// The default is set to return `Ok(())` without doing something to net enforce every
    /// ItemDispatcher to implement it.
    fn dispatch_kb(&self, _: &ContextKey, _: Kb) -> Result<(), StorageError> {
        Ok(())
    }
    /// Stores an advisory
    fn dispatch_advisory(&self, _: &str, _: Option<NotusAdvisory>) -> Result<(), StorageError>;
}

/// Collects the information while being in a description run and calls the dispatch method
/// on exit.
pub struct PerItemDispatcher<S>
where
    S: ItemDispatcher,
{
    nvt: Arc<Mutex<Option<Nvt>>>,
    dispatcher: S,
}

impl<S> PerItemDispatcher<S>
where
    S: ItemDispatcher,
{
    /// Creates a new ItemDispatcher without a feed_version and nvt.
    pub fn new(dispatcher: S) -> Self {
        Self {
            nvt: Arc::new(Mutex::new(None)),
            dispatcher,
        }
    }

    fn store_nvt_field(&self, f: NVTField) -> Result<(), StorageError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| StorageError::Dirty(format!("{x}")))?;
        let mut nvt = data.clone().unwrap_or_default();

        match f {
            NVTField::Oid(oid) => nvt.oid = oid,
            NVTField::FileName(s) => nvt.filename = s,
            NVTField::Version(s) => {
                return self.dispatcher.dispatch_feed_version(s);
            }
            NVTField::Name(s) => nvt.name = s,
            NVTField::Tag(key, name) => {
                nvt.tag.insert(key, name);
            }
            NVTField::Dependencies(s) => nvt.dependencies.extend(s),
            NVTField::RequiredKeys(s) => nvt.required_keys.extend(s),
            NVTField::MandatoryKeys(s) => nvt.mandatory_keys.extend(s),
            NVTField::ExcludedKeys(s) => nvt.excluded_keys.extend(s),
            NVTField::RequiredPorts(s) => nvt.required_ports.extend(s),
            NVTField::RequiredUdpPorts(s) => nvt.required_udp_ports.extend(s),
            NVTField::Preference(s) => nvt.preferences.push(s),
            NVTField::Reference(s) => nvt.references.extend(s),
            NVTField::Category(s) => nvt.category = s,
            NVTField::Family(s) => nvt.family = s,
            NVTField::NoOp => {}
            NVTField::Nvt(x) => nvt = x,
        };
        *data = Some(nvt);
        Ok(())
    }
}

impl<S> Dispatcher for PerItemDispatcher<S>
where
    S: ItemDispatcher + Send + Sync,
{
    fn dispatch(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        match scope {
            Field::NVT(nvt) => self.store_nvt_field(nvt),
            Field::KB(kb) => self.dispatcher.dispatch_kb(key, kb),
            Field::NotusAdvisory(adv) => self.dispatcher.dispatch_advisory(key.as_ref(), *adv),
            Field::Result(result) => self.dispatch(key, Field::Result(result)),
        }
    }

    fn dispatch_replace(&self, key: &ContextKey, scope: Field) -> Result<(), StorageError> {
        match scope {
            Field::NVT(nvt) => self.store_nvt_field(nvt),
            Field::KB(kb) => self.dispatcher.dispatch_kb(key, kb),
            Field::NotusAdvisory(adv) => self.dispatcher.dispatch_advisory(key.as_ref(), *adv),
            Field::Result(result) => self.dispatch(key, Field::Result(result)),
        }
    }

    fn on_exit(&self, _: &ContextKey) -> Result<(), StorageError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| StorageError::Dirty(format!("{x}")))?;
        self.dispatcher
            .dispatch_nvt(data.clone().unwrap_or_default())?;
        *data = None;
        Ok(())
    }
}

impl<S> Retriever for PerItemDispatcher<S>
where
    S: ItemDispatcher + Retriever,
{
    fn retrieve(
        &self,
        key: &ContextKey,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = Field>>, StorageError> {
        self.dispatcher.retrieve(key, scope)
    }

    fn retrieve_by_field(
        &self,
        field: Field,
        scope: Retrieve,
    ) -> Result<Box<dyn Iterator<Item = (ContextKey, Field)>>, StorageError> {
        self.dispatcher.retrieve_by_field(field, scope)
    }

    fn retrieve_by_fields(&self, field: Vec<Field>, scope: Retrieve) -> FieldKeyResult {
        self.dispatcher.retrieve_by_fields(field, scope)
    }
}

impl<S> Remover for PerItemDispatcher<S>
where
    S: ItemDispatcher + Remover,
{
    fn remove_kb(
        &self,
        key: &ContextKey,
        kb_key: Option<String>,
    ) -> Result<Option<Vec<Kb>>, StorageError> {
        self.dispatcher.remove_kb(key, kb_key)
    }

    fn remove_result(
        &self,
        key: &ContextKey,
        result_id: Option<usize>,
    ) -> Result<Option<Vec<models::Result>>, StorageError> {
        self.dispatcher.remove_result(key, result_id)
    }
}

#[cfg(test)]
mod tests {

    macro_rules! assert_tag_key {
        ($($matcher:ident => $key:ident),+) => {
            $(
            #[test]
            fn $matcher() {
                use super::TagKey::*;
                use super::*;
                assert_eq!(TagKey::from_str(stringify!($matcher)), Ok($key));
                assert_eq!(TagKey::from_str(stringify!($matcher)).unwrap().as_ref(), stringify!($matcher));
            }
            )*

        };
    }

    assert_tag_key! {
        affected => Affected,
        creation_date => CreationDate,
        //creation_time => CreationTime,
        cvss_base => CvssBase,
        cvss_base_vector => CvssBaseVector,
        deprecated => Deprecated,
        //detection => Detection,
        impact => Impact,
        insight => Insight,
        last_modification => LastModification,
        //modification_time => ModificationTime,
        qod => Qod,
        qod_type => QodType,
        //severities => Severities,
        severity_date => SeverityDate,
        severity_origin => SeverityOrigin,
        severity_vector => SeverityVector,
        solution => Solution,
        solution_method => SolutionMethod,
        solution_type => SolutionType,
        summary => Summary,
        vuldetect => Vuldetect
    }
}
