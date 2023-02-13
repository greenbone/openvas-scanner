use serde::{Deserialize, Serialize};

use crate::scan_manager::OID;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VTCollection {
    pub number_of_vts: i32,
    pub vts: Vec<VT>,
}

impl VTCollection {
    pub fn new() -> Self {
        VTCollection {
            number_of_vts: 0,
            vts: vec![],
        }
    }

    pub fn insert(&mut self, vt: VT) {
        self.vts.push(vt.clone());
        self.number_of_vts += 1;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VT {
    pub oid: OID,
    pub name: String,
    pub refs: Option<Vec<Reference>>,
    pub creation_time: i32,
    pub modification_time: i32,
    pub summary: String,
    pub affected: String,
    pub insight: String,
    pub solution: String,
    pub detection: Detection,
    pub severities: Vec<Severity>,
    pub filename: String,
    pub family: String,
    pub category: i8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Reference {
    pub reference_type: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Detection {
    pub detection_type: String,
    pub info: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Severity {
    pub severity_type: String,
    pub value: String,
    pub date: String,
}
