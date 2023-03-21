// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NVT
use std::{
    collections::HashMap,
    fmt::Display,
    marker::PhantomData,
    str::FromStr,
    sync::{Arc, Mutex},
};

use crate::{time::AsUnixTimeStamp, types, Dispatcher, Field, Kb, Retriever, StorageError};

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
            _ => return Err(StorageError::UnexpectedData(s.to_owned())),
        })
    }
}

macro_rules! make_str_lookup_enum {
    ($enum_name:ident: $doc:expr => { $($matcher:ident => $key:ident),+ }) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
        remote_vul => RemoteVul
    }
}

make_str_lookup_enum! {
    PreferenceType: "Allowed types for preferences" => {
       checkbox => CheckBox,
       entry => Entry,
       file => File,
       password => Password,
       radio => Radio,
       sshlogin => SshLogin
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
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum NVTKey {
           $(
             #[doc = $doc]
             $name
           ),*
        }
    };
}

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
    r###"For deprecated functions"### =>
    NoOp
}

/// Preferences that can be set by a user when running a script.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// TagValue is a type containing value types of script_tag
pub type TagValue = types::Primitive;

impl TagValue {
    /// Parhse the given Value based on the key to TagValue
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
pub trait NvtDispatcher<K> {
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
    /// Usually the NvtDispatcher is used on description = 1 runs were no KB item should occur. But
    /// to have the possibility to have shared run this interface should allow to handle it
    /// accordingly.
    /// The default is set to return `Ok(())` without doing something to net enforce every
    /// NvtDispatcher to implement it.
    fn dispatch_kb(&self, _: &K, _: Kb) -> Result<(), StorageError> {
        Ok(())
    }
}

/// Collects the information while being in a description run and calls the dispatch method
/// on exit.
pub struct PerNVTDispatcher<S, K>
where
    S: NvtDispatcher<K>,
{
    nvt: Arc<Mutex<Option<Nvt>>>,
    dispatcher: S,
    phantom: PhantomData<K>,
}

impl<S, K> PerNVTDispatcher<S, K>
where
    K: AsRef<str>,
    S: NvtDispatcher<K>,
{
    /// Creates a new NvtDispatcher without a feed_version and nvt.
    pub fn new(dispatcher: S) -> Self {
        Self {
            nvt: Arc::new(Mutex::new(None)),
            dispatcher,
            phantom: PhantomData,
        }
    }

    fn store_nvt_field(&self, f: NVTField) -> Result<(), StorageError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| StorageError::Dirty(format!("{x}")))?;
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

impl<S, K> Dispatcher<K> for PerNVTDispatcher<S, K>
where
    K: AsRef<str>,
    S: NvtDispatcher<K>,
{
    fn dispatch(&self, key: &K, scope: crate::Field) -> Result<(), StorageError> {
        match scope {
            Field::NVT(nvt) => self.store_nvt_field(nvt),
            // TODO change here to store other fields instead
            Field::KB(kb) => self.dispatcher.dispatch_kb(key, kb),
        }
    }

    fn on_exit(&self) -> Result<(), StorageError> {
        let mut data = Arc::as_ref(&self.nvt)
            .lock()
            .map_err(|x| StorageError::Dirty(format!("{x}")))?;
        self.dispatcher
            .dispatch_nvt(data.clone().unwrap_or_default())?;
        *data = None;
        Ok(())
    }
}

impl<S, K> Retriever<K> for PerNVTDispatcher<S, K>
where
    K: AsRef<str>,
    S: NvtDispatcher<K> + Retriever<K>,
{
    fn retrieve(&self, key: &K, scope: &crate::Retrieve) -> Result<Vec<Field>, StorageError> {
        self.dispatcher.retrieve(key, scope)
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
