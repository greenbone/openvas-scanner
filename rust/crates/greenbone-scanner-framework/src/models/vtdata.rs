// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines an NVT item in storage.

use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use super::KbItem;

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
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Default,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone)]
pub enum VtDataError {
    ACT(String),
    TagKey(String),
    SolutionType(String),
    QodType(String),
    PreferenceType(String),
    TagValue(String),
}

// TODO generalize and use name rather than number
impl FromStr for ACT {
    type Err = VtDataError;

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
            _ => return Err(VtDataError::ACT(s.to_owned())),
        })
    }
}

// Although I think the name would be better following the above just for consistency
impl AsRef<str> for ACT {
    fn as_ref(&self) -> &str {
        match self {
            ACT::Init => "0",
            ACT::Scanner => "1",
            ACT::Settings => "2",
            ACT::GatherInfo => "3",
            ACT::Attack => "4",
            ACT::MixedAttack => "5",
            ACT::DestructiveAttack => "6",
            ACT::Denial => "7",
            ACT::KillHost => "8",
            ACT::Flood => "9",
            ACT::End => "10",
        }
    }
}

macro_rules! make_str_lookup_enum {
    ($enum_name:ident: $doc:expr => { $($matcher:ident => $key:ident),+ }) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Ord,PartialOrd, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $enum_name {
            $(
             #[doc = concat!(stringify!($matcher))]
             $key,
            )*
        }

        impl FromStr for $enum_name {
            type Err = VtDataError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use $enum_name::*;
                match s {
                    $(
                    stringify!($matcher) => Ok($key),
                    )*
                    _ => Err(VtDataError::$enum_name(format!("{}: {}", stringify!($enum_name), s.to_owned()))),
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
        solutihttp_method => SolutionMethod, // legacy can probably removed in the next feed
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

/// Allowed types for preferences
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
enum PreferenceType {
    #[doc = "checkbox"]
    CheckBox,
    #[doc = "entry"]
    Entry,
    #[doc = "file"]
    File,
    #[doc = "password"]
    Password,
    #[doc = "radio"]
    Radio,
    #[doc = "sshlogin"]
    SshLogin,
    #[doc = "integer"]
    Integer,
}

impl FromStr for PreferenceType {
    type Err = VtDataError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use PreferenceType::*;
        match s {
            "checkbox" => Ok(CheckBox),
            "entry" => Ok(Entry),
            "file" => Ok(File),
            "password" => Ok(Password),
            "radio" => Ok(Radio),
            "sshlogin" => Ok(SshLogin),
            "integer" => Ok(Integer),
            _ => Err(VtDataError::PreferenceType(format!(
                "{:?}: {}",
                stringify!(PreferenceType),
                s.to_owned()
            ))),
        }
    }
}

impl AsRef<str> for PreferenceType {
    fn as_ref(&self) -> &str {
        use PreferenceType::*;
        match self {
            CheckBox => "checkbox",
            Entry => "entry",
            File => "file",
            Password => "password",
            Radio => "radio",
            SshLogin => "sshlogin",
            Integer => "integer",
        }
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

/// Preferences that can be set by a user when running a script.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NvtPreference {
    /// Preference ID
    id: Option<i32>,
    /// Preference type
    class: PreferenceType,
    /// Name of the preference
    name: String,
    /// Default value of the preference
    default: String,
}

/// References defines where the information for that vulnerability attack is from.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NvtRef {
    /// Reference type ("cve", "bid", ...)
    class: String,
    /// Actual reference ID ("CVE-2018-1234", etc)
    id: String,
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

impl NvtPreference {
    /// Returns id
    fn id(&self) -> Option<i32> {
        self.id
    }

    /// Returns name
    fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns default
    fn default(&self) -> &str {
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
pub type TagValue = KbItem;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
/// Structure to hold a NVT
pub struct VTData {
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
