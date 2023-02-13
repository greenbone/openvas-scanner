use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Results {
    pub new_results: Vec<Result>,
    pub old_results: Vec<Result>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Result {
    pub name: String,
    pub result_type: String,
    pub severity: Option<f32>,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub oid: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub qod: Option<i8>,
    pub uri: Option<String>,
    pub description: String,
}
