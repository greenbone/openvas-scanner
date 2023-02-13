use std::sync::Arc;

use crate::{
    models::{
        result::Result,
        scan::Scan,
        status,
        vts::{VTCollection, VT},
    },
    scan_manager::{ScanID, ScanManager},
};
use rocket::{
    delete, get, http::Status, post, response::status::Created, routes, serde::json::Json,
    tokio::sync::RwLock, uri, Build, Rocket, State,
};
use uuid::Uuid;

type ScanManagerType = Arc<RwLock<dyn ScanManager + Send + Sync>>;

/// This is a Webserver meant to be used as an API to a given ScanManager
pub struct Webserver {
    scan_manager: ScanManagerType,
}

impl Webserver {
    /// Create a new Webserver with a given ScanManager
    pub fn new(scan_manager: impl ScanManager + 'static + Send + Sync) -> Self {
        Webserver {
            scan_manager: Arc::new(RwLock::new(scan_manager)),
        }
    }

    /// Start the Webserver
    pub fn run(self) -> Rocket<Build> {
        rocket::build()
            .mount(
                "/",
                routes![
                    start_scan,
                    get_scan,
                    get_results,
                    pop_results,
                    get_status,
                    delete_scan,
                    stop_scan,
                    get_vts,
                    get_vt
                ],
            )
            .manage(self.scan_manager)
    }
}

#[post("/scans", format = "json", data = "<scan>")]
async fn start_scan(scan: Json<Scan>, manager: &State<ScanManagerType>) -> Created<Json<ScanID>> {
    // Mutex
    let mut scan_manager = manager.write().await;

    // Add scan to manager
    let scan_id = scan_manager.start_scan(scan.0);

    // Get location of the new data
    let location = uri!("/", get_scan(scan_id));

    // Generate response
    Created::new(location.to_string()).body(Json(scan_id))
}

#[get("/scans/<scan_id>")]
async fn get_scan(scan_id: Uuid, manager: &State<ScanManagerType>) -> Option<Json<Scan>> {
    // Mutex
    let scan_manager = manager.write().await;

    // Get Scan from manager
    scan_manager
        .get_scan(scan_id)
        .map(|scan| Json(scan.clone()))
}

#[get("/scans/<scan_id>/results")]
async fn get_results(scan_id: Uuid, manager: &State<ScanManagerType>) -> Option<Json<Vec<Result>>> {
    // Mutex
    let scan_manager = manager.write().await;

    // Get Results from Scan
    scan_manager
        .get_results(scan_id)
        .map(|results| Json(results.clone()))
}

#[post("/scans/<scan_id>/results")]
async fn pop_results(scan_id: Uuid, manager: &State<ScanManagerType>) -> Option<Json<Vec<Result>>> {
    // Mutex
    let mut scan_manager = manager.write().await;

    // Get new results from Scan
    scan_manager
        .pop_results(scan_id)
        .map(|results| Json(results.clone()))
}

#[get("/scans/<scan_id>/status")]
async fn get_status(
    scan_id: Uuid,
    manager: &State<ScanManagerType>,
) -> Option<Json<status::Status>> {
    // Mutex
    let scan_manager = manager.write().await;

    scan_manager
        .get_status(scan_id)
        .map(|stat| Json(stat.clone()))
}

#[delete("/scans/<scan_id>")]
async fn delete_scan(scan_id: Uuid, manager: &State<ScanManagerType>) -> Status {
    // Mutex
    let mut scan_manager = manager.write().await;

    // Delete scan
    match scan_manager.delete_scan(scan_id) {
        Some(_) => Status::Ok,
        None => Status::BadRequest,
    }
}

#[post("/scans/<scan_id>")]
async fn stop_scan(scan_id: Uuid, manager: &State<ScanManagerType>) -> Status {
    // Mutex
    let mut scan_manager = manager.write().await;

    match scan_manager.stop_scan(scan_id) {
        Some(_) => Status::Ok,
        None => Status::BadRequest,
    }
}

#[get("/vts?<query>")]
async fn get_vts(query: &str, manager: &State<ScanManagerType>) -> Option<Json<VTCollection>> {
    // Mutex
    let scan_manager = manager.write().await;

    // Get VTs with query
    scan_manager
        .get_vts(query)
        .map(|vt_collection| Json(vt_collection.clone()))
}

#[get("/vts/<oid>")]
async fn get_vt(oid: &str, manager: &State<ScanManagerType>) -> Option<Json<VT>> {
    // Mutex
    let scan_manager = manager.write().await;

    // Get VT from manager
    scan_manager.get_vt(oid).map(|vt| Json(vt.clone()))
}
