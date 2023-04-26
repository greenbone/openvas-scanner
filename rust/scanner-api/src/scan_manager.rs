use std::{cmp::min, collections::HashMap, fmt::Display};

use models::json::{
    result::Result as ScanResult,
    scan::Scan,
    scan_action::Action,
    status::{Phase, Status},
};

use crate::error::APIError;

pub type ScanID = String;
pub type OID = String;

pub struct Phases {
    phases: Vec<Phase>,
}

impl Display for Phases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.phases
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("|")
        )
    }
}

impl From<Vec<Phase>> for Phases {
    fn from(value: Vec<Phase>) -> Self {
        Self { phases: value }
    }
}

/// ScanManager trait. Used for the API to interact with the Scan Management.
pub trait ScanManager {
    /// Create a new Scan with a unique Scan ID
    fn create_scan(&mut self, scan: Scan) -> Result<ScanID, APIError>;
    /// Perform an action on a scan
    fn scan_action(&mut self, scan_id: ScanID, action: Action) -> Result<(), APIError>;
    /// Get meta information about a scan
    fn get_scan(&self, id: ScanID) -> Result<Scan, APIError>;
    /// Get result information about a scan
    fn get_results(
        &self,
        id: ScanID,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Vec<ScanResult>, APIError>;
    /// Get status information about a scan
    fn get_status(&self, id: ScanID) -> Result<Status, APIError>;
    /// Delete a scan
    fn delete_scan(&mut self, id: ScanID) -> Result<(), APIError>;
}

/// Default implementation of the ScanManager trait. This does not interact with an actual scan
/// and only manages scan information. No scan is actually started, but only simulated.
#[derive(Default)]
pub struct DefaultScanManager {
    /// List of scan meta information
    scans: HashMap<ScanID, Scan>,
    /// List of scan result information
    results: HashMap<ScanID, Vec<ScanResult>>,
    /// List of scan status information
    status: HashMap<ScanID, Status>,
}

impl DefaultScanManager {
    /// Create a new empty DefaultScanManager
    pub fn new() -> Self {
        Self {
            scans: HashMap::new(),
            results: HashMap::new(),
            status: HashMap::new(),
        }
    }

    /// Simulating a start scan action, by setting its status to running. Also contains simple
    /// error handling, e.g. a finished or running scan cannot be started.
    fn start_scan(&mut self, scan_id: ScanID) -> Result<(), APIError> {
        let mut status = match self.status.get_mut(&scan_id) {
            Some(x) => x,
            None => {
                return Err(APIError::ResourceNotFound {
                    message: "Unable to find the requested scan".to_string(),
                    id: scan_id,
                })
            }
        };

        match &status.status {
            Phase::Failed | Phase::Requested | Phase::Stopped => status.status = Phase::Running,
            x => {
                return Err(APIError::BadResourceState {
                    message: "The requested scan cannot be started.".to_string(),
                    expected: vec![
                        Phase::Requested.to_string(),
                        Phase::Stopped.to_string(),
                        Phase::Failed.to_string(),
                    ],
                    got: x.to_string(),
                })
            }
        }

        Ok(())
    }

    /// Simulating a stop scan action, by setting its status to stopped. Also contains simple
    /// error handling, e.g. only a running scan can be stopped.
    fn stop_scan(&mut self, scan_id: ScanID) -> Result<(), APIError> {
        match self.status.get_mut(&scan_id) {
            Some(status) => match &status.status {
                Phase::Running => status.status = Phase::Stopped,
                phase => {
                    return Err(APIError::BadResourceState {
                        message: "The requested scan cannot be stopped.".to_string(),
                        expected: vec![Phase::Running.to_string()],
                        got: phase.to_string(),
                    })
                }
            },
            None => {
                return Err(APIError::ResourceNotFound {
                    message: "Unable to find the requested scan.".to_string(),
                    id: scan_id,
                })
            }
        }
        Ok(())
    }
}

impl ScanManager for DefaultScanManager {
    fn create_scan(&mut self, scan: Scan) -> Result<ScanID, APIError> {
        let mut scan = scan;
        let id = match scan.scan_id.clone() {
            Some(x) => x,
            None => {
                let scan_id = uuid::Uuid::new_v4().to_string();
                scan.scan_id = Some(scan_id.clone());
                scan_id
            }
        };
        if self.scans.contains_key(&id) {
            return Err(APIError::ResourceExists {
                message: "The ID of the scan to create already exists.".to_string(),
                id,
            });
        }
        self.scans.insert(id.clone(), scan);
        self.results.insert(id.clone(), vec![]);
        self.status.insert(
            id.clone(),
            Status {
                start_time: None,
                end_time: None,
                status: Phase::Requested,
                host_info: None,
            },
        );
        Ok(id)
    }

    fn scan_action(&mut self, scan_id: ScanID, action: Action) -> Result<(), APIError> {
        match action {
            Action::Start => self.start_scan(scan_id),
            Action::Stop => self.stop_scan(scan_id),
        }
    }

    fn get_scan(&self, scan_id: ScanID) -> Result<Scan, APIError> {
        match self.scans.get(&scan_id) {
            Some(x) => Ok(x.clone()),
            None => Err(APIError::ResourceNotFound {
                message: "Unable to find the requested scan.".to_string(),
                id: scan_id,
            }),
        }
    }

    fn get_results(
        &self,
        scan_id: ScanID,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Vec<ScanResult>, APIError> {
        match self.results.get(&scan_id) {
            Some(x) => {
                if x.is_empty() {
                    return Ok(vec![]);
                }
                let f = first.unwrap_or(0);
                let l = last.unwrap_or(x.len() - 1);
                if f >= x.len() || f > l {
                    return Ok(vec![]);
                }
                Ok(x[f..=min(x.len() - 1, l)].to_vec())
            }
            None => Err(APIError::ResourceNotFound {
                message: "Unable to find the requested scan.".to_string(),
                id: scan_id,
            }),
        }
    }

    fn get_status(&self, scan_id: ScanID) -> Result<Status, APIError> {
        match self.status.get(&scan_id) {
            Some(x) => Ok(x.clone()),
            None => Err(APIError::ResourceNotFound {
                message: "Unable to find the requested scan.".to_string(),
                id: scan_id,
            }),
        }
    }

    fn delete_scan(&mut self, scan_id: ScanID) -> Result<(), APIError> {
        match self.status.get(&scan_id) {
            Some(status) => match &status.status {
                Phase::Failed | Phase::Stopped | Phase::Succeeded | Phase::Requested => {
                    self.scans.remove(&scan_id).unwrap();
                    self.results.remove(&scan_id).unwrap();
                    self.status.remove(&scan_id).unwrap();
                    Ok(())
                }
                phase => Err(APIError::BadResourceState {
                    message: "The requested scan cannot be deleted".to_string(),
                    expected: vec![
                        Phase::Requested.to_string(),
                        Phase::Failed.to_string(),
                        Phase::Stopped.to_string(),
                        Phase::Succeeded.to_string(),
                    ],
                    got: phase.to_string(),
                }),
            },
            None => Err(APIError::ResourceNotFound {
                message: "Unable to find the requested scan.".to_string(),
                id: scan_id,
            }),
        }
    }
}
