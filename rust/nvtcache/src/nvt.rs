use crate::dberror::RedisResult;
use chrono::prelude::*;
use sink::{NvtPreference, ACT, NvtRef};

///Alias for time stamps
type TimeT = i64;

const SUPPORTED_FORMATS: &[&str] = &[
    "%F %T %z",
    "$Date: %F %T %z",
    "%a %b %d %T %Y %z",
    "$Date: %a, %d %b %Y %T %z",
    "$Date: %a %b %d %T %Y %z",
];

/// Convert an Nvt Timestamp string to a time since epoch.
/// If it fails the conversion, return 0
pub fn parse_nvt_timestamp(str_time: &str) -> TimeT {
    // Remove the ending $
    let timestamp: Vec<&str> = str_time.split(" $").collect();
    // Remove the date in parenthesis
    let timestamp: Vec<&str> = timestamp[0].split(" (").collect();

    let mut ret = 0;
    for f in SUPPORTED_FORMATS {
        let res = DateTime::parse_from_str(timestamp[0], f);
        match res {
            Ok(ok) => {
                ret = ok.timestamp();
                break;
            }
            Err(_) => continue,
        }
    }
    ret
}


/// Structure to store NVT Severities
// Severities are stored in redis under the Tag item
// Currently not used
#[derive(Clone, Debug)]
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



#[derive(Clone, Debug)]
/// Structure to hold a NVT
pub struct Nvt {
    oid: String,
    name: String,
    filename: String,
    tag: Vec<(String, String)>,
    cvss_base: String, //Stored in redis under Tag item. Not in use.
    summary: String,          //Stored in redis under Tag item. Not in use.
    insight: String,          //Stored in redis under Tag item. Not in use.
    affected: String,         //Stored in redis under Tag item. Not in use.
    impact: String,           //Stored in redis under Tag item. Not in use.
    creation_time: TimeT,     //Stored in redis under Tag item. Not in use.
    modification_time: TimeT, //Stored in redis under Tag item. Not in use.
    solution: String,         //Stored in redis under Tag item. Not in use.
    solution_type: String,    //Stored in redis under Tag item. Not in use.
    solution_method: String,  //Stored in redis under Tag item. Not in use.
    detection: String, //Stored in redis under Tag item. Not in use.
    qod_type: String,  //Stored in redis under Tag item. Not in use.
    qod: String,       //Stored in redis under Tag item. Not in use.
    severities: Vec<NvtSeverity>, //Stored in redis under Tag item. Not in use.
    dependencies: Vec<String>,
    required_keys: Vec<String>,
    mandatory_keys: Vec<String>,
    excluded_keys: Vec<String>,
    required_ports: Vec<String>,
    required_udp_ports: Vec<String>,
    refs: Vec<NvtRef>,
    prefs: Vec<NvtPreference>,
    category: ACT,
    family: String,
}

impl Default for Nvt {
    fn default() -> Nvt {
        Nvt {
            oid: String::new(),
            name: String::new(),
            filename: String::new(),
            summary: String::new(),
            insight: String::new(),
            affected: String::new(),
            impact: String::new(),
            creation_time: 0,
            modification_time: 0,
            solution: String::new(),
            solution_type: String::new(),
            solution_method: String::new(),
            tag: vec![],
            cvss_base: String::new(),
            dependencies: vec![],
            required_keys: vec![],
            mandatory_keys: vec![],
            excluded_keys: vec![],
            required_ports: vec![],
            required_udp_ports: vec![],
            detection: String::new(),
            qod_type: String::new(),
            qod: String::new(),
            refs: vec![],
            severities: vec![],
            prefs: vec![],
            category: ACT::End,
            family: String::new(),
        }
    }
}

impl Nvt {
    /// Nvt constructor
    pub fn new() -> RedisResult<Nvt> {
        Ok(Nvt::default())
    }

    /// Set the NVT OID
    pub fn set_oid(&mut self, oid: String) {
        self.oid = oid;
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
    pub fn set_tag(&mut self, tag: Vec<(String, String)>) {
        self.tag = tag;
    }

    /// Set the NVT CVSS base
    // Not used during plugin upload.
    pub fn set_cvss_base(&mut self, cvss_base: String) {
        self.cvss_base = cvss_base;
    }

    /// Set the NVT dependencies
    pub fn set_dependencies(&mut self, dependencies: Vec<String>) {
        self.dependencies = dependencies;
    }

    /// Set the NVT required keys
    pub fn set_required_keys(&mut self, required_keys: Vec<String>) {
        self.required_keys = required_keys;
    }

    /// Set the NVT mandatory keys
    pub fn set_mandatory_keys(&mut self, mandatory_keys: Vec<String>) {
        self.mandatory_keys = mandatory_keys;
    }

    /// Set the NVT excluded keys
    pub fn set_excluded_keys(&mut self, excluded_keys: Vec<String>) {
        self.excluded_keys = excluded_keys;
    }

    /// Set the NVT required ports
    pub fn set_required_ports(&mut self, required_ports: Vec<String>) {
        self.required_ports = required_ports;
    }

    /// Set the NVT required udp ports
    pub fn set_required_udp_ports(&mut self, required_udp_ports: Vec<String>) {
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
    pub fn set_category(&mut self, category: ACT) {
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
        match name.as_str() {
            "last_modification" => {
                self.tag
                    .push((name, parse_nvt_timestamp(&value).to_string()));
            }
            "creation_date" => {
                self.tag
                    .push((name, parse_nvt_timestamp(&value).to_string()));
            }
            "severity_date" => {
                self.tag
                    .push((name, parse_nvt_timestamp(&value).to_string()));
            }
            // cvss_base is just ignored
            "cvss_base" => (),
            _ => {
                self.tag.push((name, value));
            }
        }
    }

    /// Function to add a new preference to the Nvt
    pub fn add_pref(&mut self, pref: NvtPreference) {
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
    pub fn oid(&self) -> &str {
        &self.oid
    }

    /// Get the NVT name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the NVT summary
    // Not used during plugin upload.
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Get the NVT insight
    // Not used during plugin upload.
    pub fn insight(&self) -> &str {
        &self.insight
    }

    /// Get the NVT affected
    // Not used during plugin upload.
    pub fn affected(&self) -> &str {
        &self.affected
    }

    /// Get the NVT impact
    // Not used during plugin upload.
    pub fn impact(&self) -> &str {
        &self.impact
    }

    /// Get the NVT creation_time
    // Not used during plugin upload.
    pub fn creation_time(&mut self) -> RedisResult<TimeT> {
        Ok(self.creation_time)
    }

    /// Get the NVT modification_time
    // Not used during plugin upload.
    pub fn modification_time(&mut self) -> RedisResult<TimeT> {
        Ok(self.modification_time)
    }
    /// Get the NVT solution
    // Not used during plugin upload.
    pub fn solution(&self) -> &str {
        &self.solution
    }

    /// Get the NVT solution_type
    // Not used during plugin upload.
    pub fn solution_type(&self) -> &str {
        &self.solution_type
    }

    /// Get the NVT solution method
    // Not used during plugin upload.
    pub fn solution_method(&self) -> &str {
        &self.solution_method
    }

    /// Get the NVT tag
    pub fn tag(&self) -> &Vec<(String, String)> {
        &self.tag
    }

    /// Get the NVT CVSS base
    // Not used during plugin upload.
    pub fn cvss_base(&self) -> &str {
        &self.cvss_base
    }
    /// Get the NVT dependencies
    pub fn dependencies(&self) -> &Vec<String> {
        &self.dependencies
    }

    /// Get the NVT required keys
    pub fn required_keys(&self) -> &Vec<String> {
        &self.required_keys
    }

    /// Get the NVT mandatory keys
    pub fn mandatory_keys(&self) -> &Vec<String> {
        &self.mandatory_keys
    }

    /// Get the NVT excluded keys
    pub fn excluded_keys(&self) -> &Vec<String> {
        &self.excluded_keys
    }

    /// Get the NVT required ports
    pub fn required_ports(&self) -> &Vec<String> {
        &self.required_ports
    }

    /// Get the NVT required udp ports
    pub fn required_udp_ports(&self) -> &Vec<String> {
        &self.required_udp_ports
    }

    /// Get the NVT detection
    // Not used during plugin upload.
    pub fn detection(&self) -> &str {
        &self.detection
    }

    /// Get the NVT QoD Type
    // Not used during plugin upload.
    pub fn qod_type(&self) -> &str {
        &self.qod_type
    }

    /// Get the NVT QoD (Quality of Detection)
    // Not used during plugin upload.
    pub fn qod(&self) -> &str {
        &self.qod
    }

    /// Get the NVT category.
    pub fn category(&self) -> i32 {
        self.category as i32
    }

    /// Get the NVT family
    pub fn family(&self) -> &str {
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
    pub fn refs(&self) -> (String, String, String) {
        let (bids, cves, xrefs): (Vec<String>, Vec<String>, Vec<String>) =
            self.refs
                .iter()
                .fold((vec![], vec![], vec![]), |(bids, cves, xrefs), b| {
                    match b.class() {
                        "bid" => {
                            let mut new_bids = bids;
                            new_bids.push(b.id().to_string());
                            (new_bids, cves, xrefs)
                        }
                        "cve" => {
                            let mut new_cves = cves;
                            new_cves.push(b.id().to_string());
                            (bids, new_cves, xrefs)
                        }
                        _ => {
                            let mut new_xref: Vec<String> = xrefs;
                            new_xref.push(format!("{}:{}", b.class(), b.id()));
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
    pub fn prefs(&self) -> Vec<String> {
        self.prefs
            .iter()
            .map(|pref| {
                format!(
                    "{}:{}:{}:{}",
                    pref.id(),
                    pref.name(),
                    pref.class().as_ref(),
                    pref.default()
                )
            })
            .collect()
    }

    pub fn set_filename(&mut self, filename: String) {
        self.filename = filename;
    }

    pub fn filename(&self) -> &str {
        self.filename.as_ref()
    }
}
