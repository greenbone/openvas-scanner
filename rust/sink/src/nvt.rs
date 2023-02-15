// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NVT
use std::str::FromStr;

use crate::SinkError;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum ACT {
    /// Defines a initializer
    Init = 0,
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
    End,
}

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
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    "Tags of a plugin" => Tag(TagKey, String),
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
pub struct NvtRef {
    /// Reference type ("cve", "bid", ...)
    pub class: String,
    /// Actual reference ID ("CVE-2018-1234", etc)
    pub id: String,
    /// Optional additional text
    pub text: Option<String>,
}

impl From<(&str, &str)> for NvtRef {
    fn from(value: (&str, &str)) -> Self {
        let (class, id) = value;
        Self {
            class: class.to_owned(),
            id: id.to_owned(),
            text: None,
        }
    }
}

impl From<(&str, String)> for NvtRef {
    fn from(value: (&str, String)) -> Self {
        let (class, id) = value;
        Self {
            class: class.to_owned(),
            id,
            text: None,
        }
    }
}
impl NvtRef {
    pub fn new(class: String, id: String, text: Option<String>) -> Self {
        Self { class, id, text }
    }
    pub fn class(&self) -> &str {
        self.class.as_ref()
    }

    pub fn id(&self) -> &str {
        self.id.as_ref()
    }

    pub fn text(&self) -> Option<&String> {
        self.text.as_ref()
    }
}

impl NvtPreference {
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    pub fn class(&self) -> PreferenceType {
        self.class
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn default(&self) -> &str {
        self.default.as_ref()
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
