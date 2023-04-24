use serde::{Deserialize, Serialize};

use super::{credential::Credential, port::Port};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Target {
    pub hosts: Vec<String>,
    pub ports: Vec<Port>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<Credential>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alive_test_ports: Option<Vec<Port>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alive_test_methods: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_lookup_unify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_lookup_only: Option<bool>,
}
