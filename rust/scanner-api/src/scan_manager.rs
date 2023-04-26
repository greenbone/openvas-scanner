use std::{cmp::min, collections::HashMap, fmt::Display};

use models::json::{
    result::Result as ScanResult,
    scan::Scan,
    scan_action::Action,
    status::{Phase, Status},
};

pub type ScanID = String;
pub type OID = String;

pub struct Phases {
    phases: Vec<Phase>,
}

/// Types of errors that can be generated, when interacting with the ScanManager
pub enum ScanErrorKind {
    ScanNotFound(String),
    BadScanStatus { expected: Phases, got: Phase },
    ActionNotSupported(String),
    ScanAlreadyExists(String),
    BadRangeFormat(String),
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

impl Display for ScanErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScanNotFound(x) => write!(f, "scan with ID {x} not found"),
            Self::BadScanStatus { expected, got } => {
                write!(f, "bad scan status, expected {expected}, got {got}")
            }
            Self::ActionNotSupported(x) => write!(f, "action {x} not supported"),
            Self::ScanAlreadyExists(x) => write!(f, "scan with ID {x} already exists"),
            Self::BadRangeFormat(x) => {
                write!(f, "bad range format {x}, expected <number>[-<number>]")
            }
        }
    }
}

/// ScanManager trait. Used for the API to interact with the Scan Management.
pub trait ScanManager {
    /// Create a new Scan with a unique Scan ID
    fn create_scan(&mut self, scan: Scan) -> Result<ScanID, ScanErrorKind>;
    /// Perform an action on a scan
    fn scan_action(&mut self, scan_id: ScanID, action: Action) -> Result<(), ScanErrorKind>;
    /// Get meta information about a scan
    fn get_scan(&self, id: ScanID) -> Result<Scan, ScanErrorKind>;
    /// Get result information about a scan
    fn get_results(
        &self,
        id: ScanID,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Vec<ScanResult>, ScanErrorKind>;
    /// Get status information about a scan
    fn get_status(&self, id: ScanID) -> Result<Status, ScanErrorKind>;
    /// Delete a scan
    fn delete_scan(&mut self, id: ScanID) -> Result<(), ScanErrorKind>;
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
    fn start_scan(&mut self, scan_id: ScanID) -> Result<(), ScanErrorKind> {
        let mut status = match self.status.get_mut(&scan_id) {
            Some(x) => x,
            None => return Err(ScanErrorKind::ScanNotFound(scan_id)),
        };

        match &status.status {
            Phase::Failed | Phase::Requested | Phase::Stopped => status.status = Phase::Running,
            x => {
                return Err(ScanErrorKind::BadScanStatus {
                    expected: vec![Phase::Failed, Phase::Requested, Phase::Stopped].into(),
                    got: x.clone(),
                })
            }
        }

        Ok(())
    }

    /// Simulating a stop scan action, by setting its status to stopped. Also contains simple
    /// error handling, e.g. only a running scan can be stopped.
    fn stop_scan(&mut self, id: ScanID) -> Result<(), ScanErrorKind> {
        match self.status.get_mut(&id) {
            Some(status) => match &status.status {
                Phase::Running => status.status = Phase::Stopped,
                phase => {
                    return Err(ScanErrorKind::BadScanStatus {
                        expected: vec![Phase::Running].into(),
                        got: phase.clone(),
                    })
                }
            },
            None => return Err(ScanErrorKind::ScanNotFound(id)),
        }
        Ok(())
    }
}

impl ScanManager for DefaultScanManager {
    fn create_scan(&mut self, scan: Scan) -> Result<ScanID, ScanErrorKind> {
        let mut scan = scan.to_owned();
        let id = match scan.scan_id.clone() {
            Some(x) => x,
            None => {
                let scan_id = uuid::Uuid::new_v4().to_string();
                scan.scan_id = Some(scan_id.clone());
                scan_id
            }
        };
        if self.scans.contains_key(&id) {
            return Err(ScanErrorKind::ScanAlreadyExists(id));
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

    fn scan_action(&mut self, scan_id: ScanID, action: Action) -> Result<(), ScanErrorKind> {
        match action {
            Action::Start => self.start_scan(scan_id),
            Action::Stop => self.stop_scan(scan_id),
        }
    }

    fn get_scan(&self, id: ScanID) -> Result<Scan, ScanErrorKind> {
        match self.scans.get(&id) {
            Some(x) => Ok(x.clone()),
            None => Err(ScanErrorKind::ScanNotFound(id)),
        }
    }

    fn get_results(
        &self,
        id: ScanID,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Vec<ScanResult>, ScanErrorKind> {
        match self.results.get(&id) {
            Some(x) => {
                if x.is_empty() {
                    return Ok(vec![]);
                }
                let f = match first {
                    Some(y) => y,
                    None => 0,
                };
                let l = match last {
                    Some(y) => y,
                    None => x.len() - 1,
                };
                if f >= x.len() || f > l {
                    return Ok(vec![]);
                }
                Ok(x[f..=min(x.len() - 1, l)].to_vec())
            }
            None => Err(ScanErrorKind::ScanNotFound(id)),
        }
    }

    fn get_status(&self, id: ScanID) -> Result<Status, ScanErrorKind> {
        match self.status.get(&id) {
            Some(x) => Ok(x.clone()),
            None => Err(ScanErrorKind::ScanNotFound(id)),
        }
    }

    fn delete_scan(&mut self, id: ScanID) -> Result<(), ScanErrorKind> {
        match self.status.get(&id) {
            Some(status) => match &status.status {
                Phase::Failed | Phase::Stopped | Phase::Succeeded | Phase::Requested => {
                    self.scans.remove(&id).unwrap();
                    self.results.remove(&id).unwrap();
                    self.status.remove(&id).unwrap();
                    Ok(())
                }
                phase => Err(ScanErrorKind::BadScanStatus {
                    expected: vec![
                        Phase::Requested,
                        Phase::Failed,
                        Phase::Stopped,
                        Phase::Succeeded,
                    ]
                    .into(),
                    got: phase.clone(),
                }),
            },
            None => Err(ScanErrorKind::ScanNotFound(id)),
        }
    }
}
