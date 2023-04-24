use std::{collections::HashMap, fmt::Display};

use models::json::{
    result::Result as ScanResult,
    scan::Scan,
    status::{Phase, Status},
};

pub type ScanID = String;
pub type OID = String;

pub enum ScanAction {
    Start,
    Stop,
}

pub struct Phases {
    phases: Vec<Phase>,
}

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

pub trait ScanManager {
    fn create_scan(&mut self, scan: Scan) -> Result<ScanID, ScanErrorKind>;
    fn scan_action(&mut self, scan_id: ScanID, action: ScanAction) -> Result<(), ScanErrorKind>;
    fn get_scan(&self, id: ScanID) -> Result<Scan, ScanErrorKind>;
    fn get_results(
        &self,
        id: ScanID,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Vec<ScanResult>, ScanErrorKind>;
    fn get_status(&self, id: ScanID) -> Result<Status, ScanErrorKind>;
    fn delete_scan(&mut self, id: ScanID) -> Result<(), ScanErrorKind>;
}

#[derive(Default)]
pub struct DefaultScanManager {
    scans: HashMap<ScanID, Scan>,
    results: HashMap<ScanID, Vec<ScanResult>>,
    status: HashMap<ScanID, Status>,
}

impl DefaultScanManager {
    pub fn new() -> Self {
        Self {
            scans: HashMap::new(),
            results: HashMap::new(),
            status: HashMap::new(),
        }
    }

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

    fn scan_action(&mut self, scan_id: ScanID, action: ScanAction) -> Result<(), ScanErrorKind> {
        match action {
            ScanAction::Start => self.start_scan(scan_id),
            ScanAction::Stop => self.stop_scan(scan_id),
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
                let f = match first {
                    Some(y) => y,
                    None => 0,
                };
                let l = match last {
                    Some(y) => y,
                    None => x.len() - 1,
                };
                Ok(x[f..=l].to_vec())
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
