// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NVT
use std::{
    collections::HashMap,
    fmt::Display,
    str::FromStr,
    sync::{Arc, Mutex},
};

use crate::{time::AsUnixTimeStamp, Dispatch, Sink, SinkError};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Default)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
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
    type Err = SinkError;

    // Iis defined as a numeric value instead of string representations due to downwards compatible reasons.
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
            _ => return Err(SinkError::UnexpectedData(s.to_owned())),
        })
    }
}

macro_rules! make_str_lookup_enum {
    ($enum_name:ident: $doc:expr => { $($matcher:ident => $key:ident),+ }) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde_support" , derive(serde::Serialize, serde::Deserialize))]
        pub enum $enum_name {
            $(
             #[doc = concat!(stringify!($matcher))]
             $key,
            )*
        }

        impl FromStr for $enum_name {
            type Err = SinkError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use $enum_name::*;
                match s {
                    $(
                    stringify!($matcher) => Ok($key),
                    )*
                    _ => Err(SinkError::UnexpectedData(s.to_owned())),
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
        creation_time => CreationTime,
        cvss_base => CvssBase,
        cvss_base_vector => CvssBaseVector,
        deprecated => Deprecated,
        detection => Detection,
        impact => Impact,
        insight => Insight,
        last_modification => LastModification,
        modification_time => ModificationTime,
        qod => Qod,
        qod_type => QodType,
        severities => Severities,
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

make_str_lookup_enum! {
    PreferenceType: "Allowed types for preferences" => {
       checkbox => CheckBox,
       entry => Entry,
       file => File,
       password => Password,
       radio => Radio,
       sshlogin => SSHLogin
    }
}

macro_rules! make_fields {

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
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum NVTKey {
           $(
             #[doc = $doc]
             $name
           ),*
        }
    };
}

make_fields! {
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
    r###"For deprecated functions"### =>
    NoOp
}

/// Preferences that can be set by a user when running a script.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
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

/// Represent a value of the key
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_support", serde(untagged))]
pub enum TagValue {
    /// A tag with a free form field
    String(String),
    /// Timestamp value
    UnixTimeStamp(i64),
}

impl Display for TagValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TagValue::String(s) => write!(f, "{s}"),
            TagValue::UnixTimeStamp(s) => write!(f, "{s}"),
        }
    }
}

impl TagValue {
    /// Parhse the given Value based on the key to TagValue
    pub fn parse<V: ToString>(key: TagKey, value: V) -> Option<Self> {
        match key {
            TagKey::CreationDate | TagKey::LastModification | TagKey::SeverityDate => {
                Some(Self::UnixTimeStamp(
                    (&value.to_string() as &str)
                        .as_timestamp()
                        .unwrap_or_default(),
                ))
            }
            TagKey::CvssBase => None,
            _ => Some(Self::String(value.to_string())),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
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
    pub tag: HashMap<TagKey, TagValue>,
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

/// Is a specialized Dispatcher for NVT information within the description block.
pub trait NvtDispatcher {
    /// Dispatches the feed version as well as NVT.
    ///
    /// The NVT is collected when a description run is finished.
    fn dispatch_nvt(&self, nvt: Nvt) -> Result<(), SinkError>;
    /// Dispatches the feed_version.
    ///
    /// Feed version is usually read once.
    fn dispatch_feed_version(&self, version: String) -> Result<(), SinkError>;
}

/// Collects the information while being in a description run and calls the dispatch method
/// on exit.
pub struct PerNVTSink<S>
where
    S: NvtDispatcher,
{
    nvt: Arc<Mutex<Option<Nvt>>>,
    dispatcher: S,
}

impl<S> PerNVTSink<S>
where
    S: NvtDispatcher,
{
    /// Creates a new NvtDispatcher without a feed_version and nvt.
    pub fn new(dispatcher: S) -> Self {
        Self {
            nvt: Arc::new(Mutex::new(None)),
            dispatcher,
        }
    }

    fn store_nvt_field(&self, f: NVTField) -> Result<(), SinkError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| SinkError::Dirty(format!("{x}")))?;
        let mut nvt = data.clone().unwrap_or_default();

        // TODO optimize
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
        };
        *data = Some(nvt);
        Ok(())
    }
}

impl<S> Sink for PerNVTSink<S>
where
    S: NvtDispatcher,
{
    fn dispatch(&self, _: &str, scope: crate::Dispatch) -> Result<(), SinkError> {
        match scope {
            Dispatch::NVT(nvt) => self.store_nvt_field(nvt),
        }
    }

    fn on_exit(&self) -> Result<(), SinkError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| SinkError::Dirty(format!("{x}")))?;
        self.dispatcher
            .dispatch_nvt(data.clone().unwrap_or_default())?;
        *data = None;
        Ok(())
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
        creation_time => CreationTime,
        cvss_base => CvssBase,
        cvss_base_vector => CvssBaseVector,
        deprecated => Deprecated,
        detection => Detection,
        impact => Impact,
        insight => Insight,
        last_modification => LastModification,
        modification_time => ModificationTime,
        qod => Qod,
        qod_type => QodType,
        severities => Severities,
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
