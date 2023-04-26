use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanAction {
    pub action: Action,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Action {
    #[serde(rename = "start")]
    Start,
    #[serde(rename = "stop")]
    Stop,
}
