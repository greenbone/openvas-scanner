use serde::{Deserialize, Serialize};

use super::{snmp::SNMP, up::UP, usk::USK};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    pub service: String,
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<UP>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usk: Option<USK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snmp: Option<SNMP>,
}
