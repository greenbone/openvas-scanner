use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Result {
    pub id: usize,
    #[serde(rename = "type")]
    pub r_type: String,
    pub ip_address: String,
    pub hostname: String,
    pub oid: String,
    pub port: i16,
    pub protocol: String,
    pub message: String,
}
