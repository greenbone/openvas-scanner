use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Status {
    pub start_time: i32,
    pub end_time: i32,
    pub status: String,
    pub progress: u8,
    pub alive_hosts: u32,
    pub dead_hosts: u32,
    pub excluded_host: u32,
    pub total_host: u32,
}
