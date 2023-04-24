use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Port {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<Protocol>,
    range: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Protocol {
    #[serde(rename = "udp")]
    UDP,
    #[serde(rename = "tcp")]
    TCP,
}
