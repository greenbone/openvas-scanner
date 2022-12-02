//#![warn(missing_docs)]
//! NASL Sink defines technology indepdent sink traits, structs ..{w;

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

/// Attack Category either set by script_category or on a scan to reflect the state the scan is in
///
/// ACT are stored as integers due to the dependency to OSPD-Openvas. When this dependency vanishes they should be stored and retrieved as strings to be easier to identify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            _ => return Err(SinkError {}),
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
                    _ => Err(SinkError {}),
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

// impl FromStr for TagKey {
//     type Err;
//
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         todo!()
//     }
// }

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

    ($field_name:ident $key_name:ident $enum_doc:expr => { $($doc:expr => $name:ident $( ($($value:ident$(<$st:ident>)?),*) )?),* }) => {
        /// Fields are used to contain the value for the field
        #[doc = $enum_doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum $field_name {
            $(
             $name $( ($( $value$(<$st>)? ),*) )?
             ),*
        }

        /// Key are the keys to get the field
        #[doc = $enum_doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum $key_name {
           $(
             $name
           ),*
        }
    };
}

make_fields! {NVTField NVTKey  r###"
Represents a NVT.

NVTs are complex metadata about a plugin.
This metadata is gathered and stored by a special `description` run parsing through NASL plugins and executing special `script_*` functions.

These functions are described in the description crate within builtin crate.
"### => {
    "Is an identifying field" => Oid(String),
    "The filename of the NASL Plugin\n\nThe filename is set on a description run and is not read from the NASL script." => FileName(String),
    "The version of the NASL feed\n\nThe version is read from plugins_version.inc." => Version(String),
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
    Reference(NvtRef),
    r###"Category of a plugin
    
    Category will be used to identify the type of the NASL plugin."### =>
    Category(ACT),
    r###"Family"### =>
    Family(String),
    r###"For deprecated functions"### =>
    NoOp
}}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Preferences that can be overridden by a user.
pub struct NvtPreference {
    /// Preference ID
    pub id: i32,
    /// Preference type
    pub class: PreferenceType,
    /// Name of the preference
    pub name: String,
    /// Default value of the preference
    pub default: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvtRef {
    /// Reference type ("cve", "bid", ...)
    pub class: String,
    /// Actual reference ID ("CVE-2018-1234", etc)
    pub id: String,
    /// Optional additional text
    pub text: Option<String>,
}

// TODO remove getter and constructor
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
    pub fn id(&self) -> i32 {
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

/// TBD
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreType {
    /// Metadata of the NASL script.
    ///
    /// Each NASL script within the feed must provide at least
    /// - OID
    /// - filename
    /// - family
    /// - category
    NVT(NVTField),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetType {
    NVT(Option<NVTKey>),
}

/// TBD errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkError {}

/// Defines the Sink interface to distribute Scope
pub trait Sink {
    /// Stores given scope to key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn store(&self, key: &str, scope: StoreType) -> Result<(), SinkError>;
    /// Get scopes found by key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn get(&self, key: &str, scope: GetType) -> Result<Vec<StoreType>, SinkError>;

    /// On exit is called when a script exit
    ///
    /// Some database require a cleanup therefore this method is called when a script finishes.
    fn on_exit(&self) -> Result<(), SinkError>;
}

/// Contains a Vector of all stored items.
///
/// The first String statement is the used key while the Vector of Scope are the values.
type StoreItem = Vec<(String, Vec<StoreType>)>;

/// Is a inmemory sink that behaves like a Storage.
#[derive(Default)]
pub struct DefaultSink {
    /// If dirty it will not clean the data on_exit
    dirty: bool,
    /// The data storage
    ///
    /// The memory access is managed via an Arc while the Mutex ensures that only one consumer at a time is accessing it.
    data: Arc<Mutex<StoreItem>>,
}

impl DefaultSink {
    /// Creates a new DefaultSink
    pub fn new(dirty: bool) -> Self {
        Self {
            dirty,
            data: Default::default(),
        }
    }

    /// Cleanses stored data.
    pub fn cleanse(&self) {
        let mut data = Arc::as_ref(&self.data).lock().unwrap();
        data.clear();
        data.shrink_to_fit();
    }
}

impl Sink for DefaultSink {
    fn store(&self, key: &str, scope: StoreType) -> Result<(), SinkError> {
        let mut data = Arc::as_ref(&self.data).lock().unwrap();
        match data.iter_mut().find(|(k, _)| k.as_str() == key) {
            Some((_, v)) => v.push(scope),
            None => data.push((key.to_owned(), vec![scope])),
        }
        Ok(())
    }

    fn get(&self, key: &str, scope: GetType) -> Result<Vec<StoreType>, SinkError> {
        let data = Arc::as_ref(&self.data).lock().unwrap();

        match data.iter().find(|(k, _)| k.as_str() == key) {
            Some((_, v)) => Ok(v.clone()),
            None => Ok(vec![]),
        }
    }

    fn on_exit(&self) -> Result<(), SinkError> {
        if !self.dirty {
            self.cleanse();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    pub fn default_storage() -> Result<(), SinkError> {
        let storage = DefaultSink::default();
        use NVTField::*;
        use StoreType::*;
        storage.store("moep", NVT(Oid("moep".to_owned())))?;
        assert_eq!(
            storage.get("moep", GetType::NVT(None))?,
            vec![NVT(Oid("moep".to_owned()))]
        );
        Ok(())
    }
}
