use std::collections::HashMap;

use rocket::serde::{Deserialize, Serialize};

use crate::scan_manager::ScanID;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Scan {
    pub scan_id: Option<ScanID>,
    pub targets: Vec<Target>,
    pub excluded: Option<Vec<String>>,
    pub scanner_parameters: Option<HashMap<String, String>>,
    pub vts: VTs,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Target {
    pub target: Vec<String>,
    pub ports: Vec<String>,
    pub credentials: Option<Vec<Credential>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    pub service: String,
    pub port: u16,
    pub up: Option<UP>,
    pub usk: Option<USK>,
    pub snmp: Option<SNMP>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UP {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct USK {
    pub username: String,
    pub password: String,
    pub private: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SNMP {
    pub username: String,
    pub password: String,
    pub community: String,
    pub auth_algorithm: String,
    pub privacy_password: String,
    pub privacy_algorithm: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VTs {
    pub vt_single: Option<Vec<VTSingle>>,
    pub vt_group: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VTSingle {
    pub oid: String,
    pub vt_parameters: Option<HashMap<String, String>>,
}
