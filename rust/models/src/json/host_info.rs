use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostInfo {
    pub all: i32,
    pub excluded: i32,
    pub dead: i32,
    pub alive: i32,
    pub queued: i32,
    pub finished: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanning: Option<Vec<String>>,
}
