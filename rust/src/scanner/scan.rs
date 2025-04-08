use crate::{
    models::{self, ScanID, VT},
    nasl::utils::context::Target,
};

#[derive(Debug, Default)]
pub struct Scan {
    pub targets: Vec<Target>,
    pub scan_id: ScanID,
    pub vts: Vec<VT>,
}

impl From<models::Scan> for Scan {
    fn from(scan: models::Scan) -> Self {
        Self {
            targets: scan
                .target
                .hosts
                .iter()
                .map(Target::resolve_hostname)
                .collect(),
            scan_id: scan.scan_id,
            vts: scan.vts,
        }
    }
}
