use std::time::Duration;

#[derive(Default)]
pub struct Config {
    pub max_queued_scans: Option<usize>,
    pub max_running_scans: Option<usize>,
    pub min_free_mem: Option<u64>,
    pub check_interval: Duration,
}
