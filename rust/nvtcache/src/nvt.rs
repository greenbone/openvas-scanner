use crate::dberror::Result;
use std::fmt;

///Alias for time stamps
type TimeT = i64;

#[derive(Debug, PartialEq, PartialOrd)]
pub enum Category {
    ActInit = 0,
    ActScanner,
    ActSettings,
    ActGatherInfo,
    ActAttack,
    ActMixedAttack,
    ActDestructiveAttack,
    ActDenial,
    ActKillHost,
    ActFlood,
    ActEnd,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", (*self as i32).to_string())
    }
}

/// Structure to store NVT preferences
#[derive(Debug)]
pub struct NvtPref {
    /// Preference ID
    pref_id: i32,
    /// Preference type
    pref_type: String,
    /// Name of the preference
    name: String,
    /// Default value of the preference
    default: String,
}

/// Structure to store NVT References
#[derive(Debug)]
pub struct NvtRef {
    /// Reference type ("cve", "bid", ...)
    ref_type: String,
    /// Actual reference ID ("CVE-2018-1234", etc)
    ref_id: String,
    /// Optional additional text
    ref_text: String,
}

/// Structure to store NVT Severities
// Severities are stored in redis under the Tag item
// Currently not used
#[derive(Debug)]
#[allow(dead_code)]
pub struct NvtSeverity {
    /// Severity type ("cvss_base_v2", ...)
    severity_type: String,
    /// Optional: Where does the severity come from
    /// ("CVE-2018-1234", "Greenbone Research")
    origin: String,
    /// Timestamp in seconds since epoch, defaults to VT creation date.
    date: i32,
    /// The score derived from the value in range [0.0-10.0]
    score: f32,
    /// The value which corresponds to the type.
    value: String,
}

impl NvtPref {
    pub fn new(pref_id: i32, pref_type: String, name: String, default: String) -> Result<NvtPref> {
        Ok(NvtPref {
            pref_id,
            pref_type,
            name,
            default,
        })
    }
    /// Return the id of the NvtPref
    pub fn get_id(&self) -> i32 {
        self.pref_id
    }
    /// Return the type of the NvtPref
    pub fn get_type(&self) -> &str {
        &self.pref_type
    }
    /// Return the name of the NvtPref
    pub fn get_name(&self) -> &str {
        &self.name
    }
    /// Return the default value of the NvtPref
    pub fn get_default(&self) -> &str {
        &self.default
    }
}

impl NvtRef {
    /// Return a new NvtRef object with the passed values
    pub fn new(ref_type: String, ref_id: String, ref_text: String) -> Result<NvtRef> {
        Ok(NvtRef {
            ref_type,
            ref_id,
            ref_text,
        })
    }
    /// Return the type of the NvtRef
    pub fn get_type(&self) -> &str {
        &self.ref_type
    }
    /// Return the id of the NvtRef
    pub fn get_id(&self) -> &str {
        &self.ref_id
    }
    /// Return the text of the NvtRef
    pub fn get_text(&self) -> &str {
        &self.ref_text
    }
}

// Currently not used
impl NvtSeverity {
    pub fn new(
        severity_type: String,
        origin: String,
        date: i32,
        score: f32,
        value: String,
    ) -> Result<NvtSeverity> {
        Ok(NvtSeverity {
            severity_type,
            origin,
            date,
            score,
            value,
        })
    }
}

#[derive(Debug)]
/// Structure to hold a NVT
pub struct Nvt {
    oid: String,
    name: String,
    summary: String,          //Stored in redis under Tag item. Not in use.
    insight: String,          //Stored in redis under Tag item. Not in use.
    affected: String,         //Stored in redis under Tag item. Not in use.
    impact: String,           //Stored in redis under Tag item. Not in use.
    creation_time: TimeT,     //Stored in redis under Tag item. Not in use.
    modification_time: TimeT, //Stored in redis under Tag item. Not in use.
    solution: String,         //Stored in redis under Tag item. Not in use.
    solution_type: String,    //Stored in redis under Tag item. Not in use.
    solution_method: String,  //Stored in redis under Tag item. Not in use.
    tag: String,
    cvss_base: String, //Stored in redis under Tag item. Not in use.
    dependencies: String,
    required_keys: String,
    mandatory_keys: String,
    excluded_keys: String,
    required_ports: String,
    required_udp_ports: String,
    detection: String, //Stored in redis under Tag item. Not in use.
    qod_type: String,  //Stored in redis under Tag item. Not in use.
    qod: String,       //Stored in redis under Tag item. Not in use.
    refs: Vec<NvtRef>,
    severities: Vec<NvtSeverity>, //Stored in redis under Tag item. Not in use.
    prefs: Vec<NvtPref>,
    category: Category,
    family: String,
}

impl Default for Nvt {
    fn default() -> Nvt {
        Nvt {
            oid: String::new(),
            name: String::new(),
            summary: String::new(),
            insight: String::new(),
            affected: String::new(),
            impact: String::new(),
            creation_time: 0,
            modification_time: 0,
            solution: String::new(),
            solution_type: String::new(),
            solution_method: String::new(),
            tag: String::new(),
            cvss_base: String::new(),
            dependencies: String::new(),
            required_keys: String::new(),
            mandatory_keys: String::new(),
            excluded_keys: String::new(),
            required_ports: String::new(),
            required_udp_ports: String::new(),
            detection: String::new(),
            qod_type: String::new(),
            qod: String::new(),
            refs: vec![],
            severities: vec![],
            prefs: vec![],
            category: Category::ActEnd,
            family: String::new(),
        }
    }
}

impl Nvt {
    /// Nvt constructor
    pub fn new() -> Result<Nvt> {
        return Ok(Nvt::default());
    }

    /// Set the NVT OID
    pub fn set_oid(&mut self, oid: String) -> Result<()> {
        self.oid = oid;
        return Ok(());
    }

    /// Set the NVT name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Set the NVT summary
    // Not used during plugin upload.
    pub fn set_summary(&mut self, summary: String) {
        self.summary = summary;
    }

    /// Set the NVT insight
    // Not used during plugin upload.
    pub fn set_insight(&mut self, insight: String) {
        self.insight = insight;
    }

    /// Set the NVT affected
    // Not used during plugin upload.
    pub fn set_affected(&mut self, affected: String) {
        self.affected = affected;
    }

    /// Set the NVT impact
    // Not used during plugin upload.
    pub fn set_impact(&mut self, impact: String) {
        self.impact = impact;
    }

    /// Set the NVT creation_time
    // Not used during plugin upload.
    pub fn set_creation_time(&mut self, creation_time: TimeT) {
        self.creation_time = creation_time;
    }

    /// Set the NVT modification_time
    // Not used during plugin upload.
    pub fn set_modification_time(&mut self, modification_time: TimeT) {
        self.modification_time = modification_time;
    }
    /// Set the NVT solution
    // Not used during plugin upload.
    pub fn set_solution(&mut self, solution: String) {
        self.solution = solution;
    }

    /// Set the NVT solution_type
    // Not used during plugin upload.
    pub fn set_solution_type(&mut self, solution_type: String) {
        self.solution_type = solution_type;
    }

    /// Set the NVT solution method
    // Not used during plugin upload.
    pub fn set_solution_method(&mut self, solution_method: String) {
        self.solution_method = solution_method;
    }

    /// Set the NVT tag
    pub fn set_tag(&mut self, tag: String) {
        self.tag = tag;
    }

    /// Set the NVT CVSS base
    // Not used during plugin upload.
    pub fn set_cvss_base(&mut self, cvss_base: String) {
        self.cvss_base = cvss_base;
    }
    /// Set the NVT dependencies
    pub fn set_dependencies(&mut self, dependencies: String) {
        self.dependencies = dependencies;
    }

    /// Set the NVT required keys
    pub fn set_required_keys(&mut self, required_keys: String) {
        self.required_keys = required_keys;
    }

    /// Set the NVT mandatory keys
    pub fn set_mandatory_keys(&mut self, mandatory_keys: String) {
        self.mandatory_keys = mandatory_keys;
    }

    /// Set the NVT excluded keys
    pub fn set_excluded_keys(&mut self, excluded_keys: String) {
        self.excluded_keys = excluded_keys;
    }

    /// Set the NVT required ports
    pub fn set_required_ports(&mut self, required_ports: String) {
        self.required_ports = required_ports;
    }

    /// Set the NVT required udp ports
    pub fn set_required_udp_ports(&mut self, required_udp_ports: String) {
        self.required_udp_ports = required_udp_ports;
    }

    /// Set the NVT detection
    // Not used during plugin upload.
    pub fn set_detection(&mut self, detection: String) {
        self.detection = detection;
    }

    /// Set the NVT QoD Type
    // Not used during plugin upload.
    pub fn set_qod_type(&mut self, qod_type: String) {
        self.qod_type = qod_type;
    }

    /// Set the NVT QoD (Quality of Detection)
    // Not used during plugin upload.
    pub fn set_qod(&mut self, qod: String) {
        self.qod = qod;
    }

    /// Set the NVT category. Check that category is a valid Category
    pub fn set_category(&mut self, category: Category) {
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
        let mut new_value = value;
        let current_tag = &self.tag;

        match name.as_str() {
            "last_modification" => {
                //TODO: convert the value to seconds since epoch
                new_value = 1234.to_string();
            }
            "creation_date" => {
                //TODO: convert the value to seconds since epoch
                new_value = 1234.to_string();
            }
            "severity_date" => {
                //TODO: convert the value to seconds since epoch
                new_value = 1234.to_string();
            }
            "cvss_base" => return,
            _ => (),
        }
        if self.tag.is_empty() {
            self.tag = [name, "=".to_string(), new_value].concat();
        } else {
            self.tag = [
                current_tag.to_string(),
                "|".to_string(),
                name,
                "=".to_string(),
                new_value,
            ]
            .concat();
        }
    }

    /// Function to add a new preference to the Nvt
    pub fn add_pref(&mut self, pref: NvtPref) {
        self.prefs.push(pref);
    }

    /// Function to add a new reference to the Nvt
    pub fn add_ref(&mut self, nvtref: NvtRef) {
        self.refs.push(nvtref);
    }

    /// Function to add a new severity to the Nvt
    // Not used during plugin upload.
    pub fn add_severity(&mut self, severity: NvtSeverity) {
        self.severities.push(severity);
    }

    //   GET FUNCTIONS

    /// Get the NVT OID
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the NVT name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the NVT summary
    // Not used during plugin upload.
    pub fn get_summary(&self) -> &str {
        &self.summary
    }

    /// Get the NVT insight
    // Not used during plugin upload.
    pub fn get_insight(&self) -> &str {
        &self.insight
    }

    /// Get the NVT affected
    // Not used during plugin upload.
    pub fn get_affected(&self) -> &str {
        &self.affected
    }

    /// Get the NVT impact
    // Not used during plugin upload.
    pub fn get_impact(&self) -> &str {
        &self.impact
    }

    /// Get the NVT creation_time
    // Not used during plugin upload.
    pub fn get_creation_time(&mut self) -> Result<TimeT> {
        Ok(self.creation_time.clone())
    }

    /// Get the NVT modification_time
    // Not used during plugin upload.
    pub fn get_modification_time(&mut self) -> Result<TimeT> {
        Ok(self.modification_time.clone())
    }
    /// Get the NVT solution
    // Not used during plugin upload.
    pub fn get_solution(&self) -> &str {
        &self.solution
    }

    /// Get the NVT solution_type
    // Not used during plugin upload.
    pub fn get_solution_type(&self) -> &str {
        &self.solution_type
    }

    /// Get the NVT solution method
    // Not used during plugin upload.
    pub fn get_solution_method(&self) -> &str {
        &self.solution_method
    }

    /// Get the NVT tag
    pub fn get_tag(&self) -> &str {
        &self.tag
    }

    /// Get the NVT CVSS base
    // Not used during plugin upload.
    pub fn get_cvss_base(&self) -> &str {
        &self.cvss_base
    }
    /// Get the NVT dependencies
    pub fn get_dependencies(&self) -> &str {
        &self.dependencies
    }

    /// Get the NVT required keys
    pub fn get_required_keys(&self) -> &str {
        &self.required_keys
    }

    /// Get the NVT mandatory keys
    pub fn get_mandatory_keys(&self) -> &str {
        &self.mandatory_keys
    }

    /// Get the NVT excluded keys
    pub fn get_excluded_keys(&self) -> &str {
        &self.excluded_keys
    }

    /// Get the NVT required ports
    pub fn get_required_ports(&self) -> &str {
        &self.required_ports
    }

    /// Get the NVT required udp ports
    pub fn get_required_udp_ports(&self) -> &str {
        &self.required_udp_ports
    }

    /// Get the NVT detection
    // Not used during plugin upload.
    pub fn get_detection(&self) -> &str {
        &self.detection
    }

    /// Get the NVT QoD Type
    // Not used during plugin upload.
    pub fn get_qod_type(&self) -> &str {
        &self.qod_type
    }

    /// Get the NVT QoD (Quality of Detection)
    // Not used during plugin upload.
    pub fn get_qod(&self) -> &str {
        &self.qod
    }

    /// Get the NVT category.
    pub fn get_category(&self) -> i32 {
        self.category as i32
    }

    /// Get the NVT family
    pub fn get_family(&self) -> &str {
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
    pub fn get_refs(&self) -> (String, String, String) {
        let (bids, cves, xrefs): (Vec<String>, Vec<String>, Vec<String>) =
            self.refs
                .iter()
                .fold((vec![], vec![], vec![]), |(bids, cves, xrefs), b| {
                    match b.get_type() {
                        "bid" => {
                            let mut new_bids = bids;
                            new_bids.push(b.get_id().to_string());
                            (new_bids, cves, xrefs)
                        }
                        "cve" => {
                            let mut new_cves = cves;
                            new_cves.push(b.get_id().to_string());
                            (bids, new_cves, xrefs)
                        }
                        _ => {
                            let mut new_xref: Vec<String> = xrefs;
                            new_xref.push(format!("{}:{}", b.get_type(), b.get_id()));
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

    /// Transforms prefs to string representatiosn {id}:{name}:{id}:{default} so that it can be stored into redis
    pub fn get_prefs(&self) -> Vec<String> {
        self.prefs
            .iter()
            .map(|pref| {
                format!(
                    "{}:{}:{}:{}",
                    pref.get_id(),
                    pref.get_name(),
                    pref.get_type(),
                    pref.get_default()
                )
            })
            .collect()
    }
}
