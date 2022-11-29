//#![warn(missing_docs)]
//! NASL Sink defines technology indepdent sink traits, structs ..{w;

use std::sync::{Arc, Mutex};

/// Attack Category either set by script_category or on a scan to reflect the state the scan is in
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
        impl $enum_name{
            /// Matches a given string and returns TagKey
            pub fn new(key: &str) -> Option<Self> {
                use $enum_name::*;
                match key {
                    $(
                    stringify!($matcher) => Some($key),
                    )*
                    _ => None,
                }
            }

            /// Returns string representation
            pub fn as_str(&self) -> &str {
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

/// NVTKeys are keys that represent a NVT
///
/// Since nasl is a iterative script language this allows the fields to be stored
/// separately and doesn't enforce a caching mechanism that may not be fitting the storage solution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NVTKey {
    /// Is an identifying field
    ///
    /// Although OID is required to find a NVT it is not required to call it first within
    /// a description block.
    /// This means that a storage implementation is required to cache everything until an OID is provided
    /// and just afterwards store the actual data
    Oid(String),
    /// The filename of the NASL Plugin
    FileName(String),
    /// The name of the NASL Plugin
    Name(String),
    /// Tags of the NASL plugin
    Tag(TagKey, String),
    /// Dependencies
    Dependencies(Vec<String>),
    /// Required keys
    ///
    /// Those keys must be set to run this script. Otherwise it will be skipped.
    RequiredKeys(Vec<String>),
    /// Mandatory keys
    ///
    /// Those keys must be set to run this script. Otherwise it will be skipped.
    MandatoryKeys(Vec<String>),
    /// Excluded keys
    ///
    /// Those keys must not be set to run this script. Otherwise it will be skipped.
    ExcludedKeys(Vec<String>),
    /// Required TCP ports
    ///
    /// Those ports must be found and open. Otherwise it will be skipped.
    RequiredPorts(Vec<String>),
    /// Required UDP ports
    ///
    /// Those ports must be found and open. Otherwise it will be skipped.
    RequiredUdpPorts(Vec<String>),
    /// Preferences that can be set by a User
    Preference(NvtPreference),
    /// Reference either cve, bid, ...
    Reference(NvtRef),
    /// Category of a plugin
    ///
    /// Category will be used to identify the type of the NASL plugin.
    Category(ACT),
    /// Family
    Family(String),
    /// For deprecated functions
    NoOp,
}

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

/// Scope defines the scope of the storage to be used
///
/// NASL knows 3 types of storage:
/// - NVT - for caching metadata of NVTs
/// - Log - for distributing / storing results or messages
/// - KB - knowledge base to be shared between NASL plugins
/// - Internal - information for the scanner application
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Metadata of the NASL script.
    ///
    /// Each NASL script within the feed must provide at least
    /// - OID
    /// - filename
    /// - family
    /// - category
    NVT(NVTKey),
}

/// TBD errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkError {}

/// Defines the Sink interface to distribute Scope
pub trait Sink {
    /// Stores given scope to key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn store(&self, key: &str, scope: Scope) -> Result<(), SinkError>;
    /// Get scopes found by key
    ///
    /// A key is usually a OID that was given when starting a script but in description run it is the filename.
    fn get(&self, key: &str) -> Result<Vec<Scope>, SinkError>;

    /// On exit is called when a script exit
    ///
    /// Some database require a cleanup therefore this method is called when a script finishes.
    fn on_exit(&self) -> Result<(), SinkError>;
}

/// Contains a Vector of all stored items.
///
/// The first String statement is the used key while the Vector of Scope are the values.
type StoreItem = Vec<(String, Vec<Scope>)>;

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
    fn store(&self, key: &str, scope: Scope) -> Result<(), SinkError> {
        let mut data = Arc::as_ref(&self.data).lock().unwrap();
        println!("storing {} => {:?}", key, scope);

        match data.iter_mut().find(|(k, _)| k.as_str() == key) {
            Some((_, v)) => v.push(scope),
            None => data.push((key.to_owned(), vec![scope])),
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Vec<Scope>, SinkError> {
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
                assert_eq!(TagKey::new(stringify!($matcher)), Some($key));
                assert_eq!(TagKey::new(stringify!($matcher)).unwrap().as_str(), stringify!($matcher));
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
        use NVTKey::*;
        use Scope::*;
        storage.store("moep", NVT(Oid("moep".to_owned())))?;
        assert_eq!(storage.get("moep")?, vec![NVT(Oid("moep".to_owned()))]);
        Ok(())
    }
}
