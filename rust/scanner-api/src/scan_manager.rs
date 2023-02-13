use std::collections::HashMap;

use uuid::Uuid;

use crate::models::{
    result::{Result, Results},
    scan::Scan,
    status::Status,
    vts::{VTCollection, VT},
};

pub type ScanID = Uuid;
pub type OID = String;

pub trait ScanManager {
    fn start_scan(&mut self, scan: Scan) -> ScanID;
    fn get_scan(&self, id: ScanID) -> Option<Scan>;
    fn get_results(&self, id: ScanID) -> Option<Vec<Result>>;
    fn pop_results(&mut self, id: ScanID) -> Option<Vec<Result>>;
    fn get_status(&self, id: ScanID) -> Option<Status>;
    fn delete_scan(&mut self, id: ScanID) -> Option<()>;
    fn stop_scan(&mut self, id: ScanID) -> Option<()>;
    fn get_vts(&self, query: &str) -> Option<VTCollection>;
    fn get_vt(&self, oid: &str) -> Option<VT>;
}

#[derive(Default)]
pub struct DefaultScanManager {
    scans: HashMap<ScanID, Scan>,
    results: HashMap<ScanID, Results>,
    status: HashMap<ScanID, Status>,

    vts: HashMap<OID, VT>,
}

impl ScanManager for DefaultScanManager {
    fn start_scan(&mut self, mut scan: Scan) -> ScanID {
        let id: ScanID;
        if scan.scan_id.is_some() {
            id = scan.scan_id.unwrap();
        } else {
            id = ScanID::new_v4();
            scan.scan_id = Some(id);
        }
        self.scans.insert(id, scan);
        self.results.insert(
            id,
            Results {
                new_results: vec![],
                old_results: vec![],
            },
        );
        self.status.insert(
            id,
            Status {
                start_time: 0,
                end_time: 0,
                status: "init".to_string(),
                progress: 0,
                alive_hosts: 0,
                dead_hosts: 0,
                excluded_host: 0,
                total_host: 0,
            },
        );
        // TODO: start actual scan
        id
    }

    fn get_scan(&self, id: ScanID) -> Option<Scan> {
        match self.scans.get(&id) {
            Some(x) => Some(x.clone()),
            None => None,
        }
    }

    fn get_results(&self, id: ScanID) -> Option<Vec<Result>> {
        match self.results.get(&id) {
            Some(x) => Some([x.new_results.clone(), x.old_results.clone()].concat()),
            None => None,
        }
    }

    fn pop_results(&mut self, id: ScanID) -> Option<Vec<Result>> {
        match self.results.get_mut(&id) {
            Some(x) => {
                let res = x.new_results.clone();
                x.old_results.append(&mut x.new_results);
                return Some(res);
            }
            None => None,
        }
    }

    fn get_status(&self, id: ScanID) -> Option<Status> {
        match self.status.get(&id) {
            Some(x) => Some(x.clone()),
            None => None,
        }
    }

    fn delete_scan(&mut self, id: ScanID) -> Option<()> {
        match self.status.get(&id) {
            Some(x) => {
                if x.status.eq("finished") {
                    self.scans.remove(&id).unwrap();
                    self.results.remove(&id).unwrap();
                    self.status.remove(&id).unwrap();
                    return Some(());
                } else {
                    return None;
                }
            }
            None => None,
        }
    }

    fn stop_scan(&mut self, id: ScanID) -> Option<()> {
        match self.status.get(&id) {
            Some(x) => {
                if x.status.eq("finished") {
                    return None;
                }
                if x.status.eq("running") {
                    // Todo Stop Scan
                    return Some(());
                }
                return self.delete_scan(id);
            }
            None => None,
        }
    }

    fn get_vts(&self, query: &str) -> Option<VTCollection> {
        let mut vt_collection = VTCollection::new();
        if query.is_empty() {
            for vt in self.vts.values() {
                vt_collection.insert(vt.clone());
            }
            return Some(vt_collection);
        }
        None
    }

    fn get_vt(&self, oid: &str) -> Option<VT> {
        match self.vts.get(oid) {
            Some(x) => Some(x.clone()),
            None => None,
        }
    }
}
