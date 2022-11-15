use crate::dberror::DbError;
use crate::dberror::Result;
use std::collections::LinkedList;

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
#[derive(Debug)]
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
    pub fn get_type(&mut self) -> String {
        return self.ref_type.clone();
    }
    /// Return the id of the NvtRef
    pub fn get_id(&mut self) -> String {
        return self.ref_id.clone();
    }
    /// Return the text of the NvtRef
    pub fn get_text(&mut self) -> String {
        return self.ref_text.clone();
    }
}

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

#[allow(dead_code)]
#[derive(Debug)]
/// Structure to hold a NVT
pub struct Nvt {
    oid: String,
    name: String,
    summary: String,
    insight: String,
    affected: String,
    impact: String,
    creation_time: TimeT,
    modification_time: TimeT,
    solution: String,
    solution_type: String,
    solution_method: String,
    tag: String,
    cvss_base: String,
    dependencies: String,
    required_keys: String,
    mandatory_keys: String,
    excluded_keys: String,
    required_ports: String,
    required_udp_ports: String,
    detection: String,
    qod_type: String,
    qod: String,
    refs: LinkedList<NvtRef>,
    severities: LinkedList<NvtSeverity>,
    prefs: LinkedList<NvtPref>,
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
            refs: LinkedList::new(),
            severities: LinkedList::new(),
            prefs: LinkedList::new(),
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

    pub fn destroy(self) {}

    /// Set the NVT OID
    pub fn set_oid(&mut self, oid: String) -> Result<()> {
        self.oid = oid;
        return Ok(());
    }

    /// Set the NVT name
    pub fn set_name(&mut self, name: String) -> Result<()> {
        self.name = name;
        return Ok(());
    }

    /// Set the NVT summary
    pub fn set_summary(&mut self, summary: String) -> Result<()> {
        self.summary = summary;
        return Ok(());
    }

    /// Set the NVT insight
    pub fn set_insight(&mut self, insight: String) -> Result<()> {
        self.insight = insight;
        return Ok(());
    }

    /// Set the NVT affected
    pub fn set_affected(&mut self, affected: String) -> Result<()> {
        self.affected = affected;
        return Ok(());
    }

    /// Set the NVT impact
    pub fn set_impact(&mut self, impact: String) -> Result<()> {
        self.impact = impact;
        return Ok(());
    }

    /// Set the NVT creation_time
    pub fn set_creation_time(&mut self, creation_time: TimeT) -> Result<()> {
        self.creation_time = creation_time;
        return Ok(());
    }

    /// Set the NVT modification_time
    pub fn set_modification_time(&mut self, modification_time: TimeT) -> Result<()> {
        self.modification_time = modification_time;
        return Ok(());
    }
    /// Set the NVT solution
    pub fn set_solution(&mut self, solution: String) -> Result<()> {
        self.solution = solution;
        return Ok(());
    }

    /// Set the NVT solution_type
    pub fn set_solution_type(&mut self, solution_type: String) -> Result<()> {
        self.solution_type = solution_type;
        return Ok(());
    }

    /// Set the NVT solution method
    pub fn set_solution_method(&mut self, solution_method: String) -> Result<()> {
        self.solution_method = solution_method;
        return Ok(());
    }

    /// Set the NVT tag
    pub fn set_tag(&mut self, tag: String) -> Result<()> {
        self.tag = tag;
        return Ok(());
    }

    /// Set the NVT CVSS base
    pub fn set_cvss_base(&mut self, cvss_base: String) -> Result<()> {
        self.cvss_base = cvss_base;
        return Ok(());
    }
    /// Set the NVT dependencies
    pub fn set_dependencies(&mut self, dependencies: String) -> Result<()> {
        self.dependencies = dependencies;
        return Ok(());
    }

    /// Set the NVT required keys
    pub fn set_required_keys(&mut self, required_keys: String) -> Result<()> {
        self.required_keys = required_keys;
        return Ok(());
    }

    /// Set the NVT mandatory keys
    pub fn set_mandatory_keys(&mut self, mandatory_keys: String) -> Result<()> {
        self.mandatory_keys = mandatory_keys;
        return Ok(());
    }

    /// Set the NVT excluded keys
    pub fn set_excluded_keys(&mut self, excluded_keys: String) -> Result<()> {
        self.excluded_keys = excluded_keys;
        return Ok(());
    }

    /// Set the NVT required ports
    pub fn set_required_ports(&mut self, required_ports: String) -> Result<()> {
        self.required_ports = required_ports;
        return Ok(());
    }

    /// Set the NVT required udp ports
    pub fn set_required_udp_ports(&mut self, required_udp_ports: String) -> Result<()> {
        self.required_udp_ports = required_udp_ports;
        return Ok(());
    }

    /// Set the NVT detection
    pub fn set_detection(&mut self, detection: String) -> Result<()> {
        self.detection = detection;
        return Ok(());
    }

    /// Set the NVT QoD Type
    pub fn set_qod_type(&mut self, qod_type: String) -> Result<()> {
        self.qod_type = qod_type;
        return Ok(());
    }

    /// Set the NVT QoD (Quality of Detection)
    pub fn set_qod(&mut self, qod: String) -> Result<()> {
        self.qod = qod;
        return Ok(());
    }

    // ^ TODO: write fn for refs, severities, prefs, which are LinkedLists

    /// Set the NVT category. Check that category is a valid Category
    pub fn set_category(&mut self, category: Category) -> Result<()> {
        if category >= Category::ActInit && category <= Category::ActEnd {
            self.category = category;
            return Ok(());
        }
        return Err(DbError::CustomErr(
            "Invalid category for an NVT".to_string(),
        ));
    }

    /// Set the NVT family
    pub fn set_family(&mut self, family: String) -> Result<()> {
        self.family = family;
        return Ok(());
    }

    /// Add a tag to the NVT tags.
    /// The tag names "severity_date", "last_modification" and
    /// "creation_date" are treated special: The value is expected
    /// to be a timestamp  and it is being converted to seconds
    /// since epoch before added as a tag value.
    /// The tag name "cvss_base" will be ignored and not added.
    pub fn add_tag(&mut self, name: String, value: String) -> Result<()> {
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
            "cvss_base" => return Ok(()),
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

        return Ok(());
    }

    /// Function to add a new preference to the Nvt
    pub fn add_pref(&mut self, pref: NvtPref) -> Result<()> {
        self.prefs.push_back(pref);
        return Ok(());
    }

    /// Function to add a new reference to the Nvt
    pub fn add_ref(&mut self, nvtref: NvtRef) -> Result<()> {
        self.refs.push_back(nvtref);
        return Ok(());
    }

    /// Function to add a new severity to the Nvt
    pub fn add_severity(&mut self, severity: NvtSeverity) -> Result<()> {
        self.severities.push_back(severity);
        return Ok(());
    }

    //   GET FUNCTIONS

    /// Get the NVT OID
    pub fn get_oid(&mut self) -> Result<String> {
        Ok(self.oid.clone())
    }

    /// Get the NVT name
    pub fn get_name(&mut self) -> Result<String> {
        Ok(self.name.clone())
    }

    /// Get the NVT summary
    pub fn get_summary(&mut self) -> Result<String> {
        Ok(self.summary.clone())
    }

    /// Get the NVT insight
    pub fn get_insight(&mut self) -> Result<String> {
        Ok(self.insight.clone())
    }

    /// Get the NVT affected
    pub fn get_affected(&mut self) -> Result<String> {
        Ok(self.affected.clone())
    }

    /// Get the NVT impact
    pub fn get_impact(&mut self) -> Result<String> {
        Ok(self.impact.clone())
    }

    /// Get the NVT creation_time
    pub fn get_creation_time(&mut self) -> Result<TimeT> {
        Ok(self.creation_time.clone())
    }

    /// Get the NVT modification_time
    pub fn get_modification_time(&mut self) -> Result<TimeT> {
        Ok(self.modification_time.clone())
    }
    /// Get the NVT solution
    pub fn get_solution(&mut self) -> Result<String> {
        Ok(self.solution.clone())
    }

    /// Get the NVT solution_type
    pub fn get_solution_type(&mut self) -> Result<String> {
        Ok(self.solution_type.clone())
    }

    /// Get the NVT solution method
    pub fn get_solution_method(&mut self) -> Result<String> {
        Ok(self.solution_method.clone())
    }

    /// Get the NVT tag
    pub fn get_tag(&mut self) -> Result<String> {
        Ok(self.tag.clone())
    }

    /// Get the NVT CVSS base
    pub fn get_cvss_base(&mut self) -> Result<String> {
        Ok(self.cvss_base.clone())
    }
    /// Get the NVT dependencies
    pub fn get_dependencies(&mut self) -> Result<String> {
        Ok(self.dependencies.clone())
    }

    /// Get the NVT required keys
    pub fn get_required_keys(&mut self) -> Result<String> {
        Ok(self.required_keys.clone())
    }

    /// Get the NVT mandatory keys
    pub fn get_mandatory_keys(&mut self) -> Result<String> {
        Ok(self.mandatory_keys.clone())
    }

    /// Get the NVT excluded keys
    pub fn get_excluded_keys(&mut self) -> Result<String> {
        Ok(self.excluded_keys.clone())
    }

    /// Get the NVT required ports
    pub fn get_required_ports(&mut self) -> Result<String> {
        Ok(self.required_ports.clone())
    }

    /// Get the NVT required udp ports
    pub fn get_required_udp_ports(&mut self) -> Result<String> {
        Ok(self.required_udp_ports.clone())
    }

    /// Get the NVT detection
    pub fn get_detection(&mut self) -> Result<String> {
        Ok(self.detection.clone())
    }

    /// Get the NVT QoD Type
    pub fn get_qod_type(&mut self) -> Result<String> {
        Ok(self.qod_type.clone())
    }

    /// Get the NVT QoD (Quality of Detection)
    pub fn get_qod(&mut self) -> Result<String> {
        Ok(self.qod.clone())
    }

    /// Get the NVT category. Check that category is a valid Category
    pub fn get_category(&mut self) -> Result<i32> {
        Ok(self.category as i32)
    }

    /// Get the NVT family
    pub fn get_family(&mut self) -> Result<String> {
        Ok(self.family.clone())
    }

    /// Get References. It returns a tuple of three strings
    /// Each string is a references type, and each string
    /// can contain a list of references of the same type.
    /// The string contains in the following types:
    /// (cve_types, bid_types, other_types)
    /// cve and bid strings are CSC strings containing only
    /// "id, id, ...", while other custom types includes the type
    /// and the string is in the format "type:id, type:id, ..."
    pub fn get_refs(&mut self) -> Result<(String, String, String)> {
        let mut bid = String::new();
        let mut cve = String::new();
        let mut xrefs = String::new();

        for r in self.refs.iter_mut() {
            let single_ref = r;
            let reftype = single_ref.get_type();

            let id = single_ref.get_id();
            match reftype.as_str() {
                "bid" => {
                    if !bid.is_empty() {
                        bid = [bid.as_str(), ", ", id.as_str()].join("");
                    } else {
                        bid = [id.as_str()].join("");
                    }
                }
                "cve" => {
                    if !cve.is_empty() {
                        cve = [cve.as_str(), ", ", id.as_str()].join("");
                    } else {
                        cve = [id.as_str()].join("");
                    }
                }
                _ => {
                    if !xrefs.is_empty() {
                        xrefs = [xrefs.as_str(), ", ", reftype.as_str(), ":", id.as_str()].join("");
                    } else {
                        xrefs = [reftype.as_str(), ":", id.as_str()].join("");
                    }
                }
            }
        }
        return Ok((cve.to_string(), bid.to_string(), xrefs.to_string()));
    }
}
