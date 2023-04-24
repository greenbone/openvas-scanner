use std::sync::Arc;

use crate::{
    scan_manager::{ScanErrorKind, ScanID, ScanManager},
    vt_manager::VTManager,
};
use models::json::{
    result::Result as ScanResult, scan::Scan, scan_action::ScanAction, status::Status as ScanStatus,
};
use rocket::{
    async_trait, delete,
    fairing::{Fairing, Info, Kind},
    get, head,
    http::{Header, Status},
    post,
    response::{status::Created, Responder},
    routes,
    serde::json::Json,
    tokio::sync::RwLock,
    uri, Build, Request, Response, Rocket, State,
};

type ScanManagerType = Arc<RwLock<dyn ScanManager + Send + Sync>>;
type VTManagerType = Arc<RwLock<dyn VTManager + Send + Sync>>;

/// Manager to handle requests regarding Scans and VTs
struct Manager {
    /// handles scan related stuff
    pub scan_manager: ScanManagerType,
    /// Handles vt related stuff
    pub vt_manager: VTManagerType,
}

/// Contains version and authentication information. Is meant to be put into the header of
/// responses.
struct HeadInformation {
    pub api_version: String,
    pub feed_version: String,
    pub authentication: String,
}

#[async_trait]
impl Fairing for HeadInformation {
    fn info(&self) -> Info {
        Info {
            name: "HEAD version Info",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _: &'r Request<'_>, response: &mut Response<'r>) {
        response.adjoin_header(Header::new("api-version", self.api_version.to_owned()));
        response.adjoin_header(Header::new("feed-version", self.feed_version.to_owned()));
        response.adjoin_header(Header::new(
            "authentication",
            self.authentication.to_owned(),
        ));
    }
}

/// This is a Webserver meant to be used as an API to a given ScanManager
pub struct Webserver {
    manager: Manager,
    head_info: HeadInformation,
}

impl Webserver {
    /// Create a new Webserver with a given ScanManager
    pub fn new(
        scan_manager: impl ScanManager + 'static + Send + Sync,
        vt_manager: impl VTManager + 'static + Send + Sync,
    ) -> Self {
        Webserver {
            manager: Manager {
                scan_manager: Arc::new(RwLock::new(scan_manager)),
                vt_manager: Arc::new(RwLock::new(vt_manager)),
            },
            // TODO: Get HeadInfo from Caller
            head_info: HeadInformation {
                api_version: "0.1".to_string(),
                feed_version: "0.1".to_string(),
                authentication: "api-key,x.509".to_string(),
            },
        }
    }

    /// Start the Webserver
    pub fn run(self) -> Rocket<Build> {
        rocket::build()
            .mount(
                "/",
                routes![
                    get_header,
                    create_scan,
                    scan_action,
                    get_scan,
                    get_results_wo_range,
                    get_results_w_range,
                    get_status,
                    delete_scan,
                    get_oids,
                ],
            )
            .manage(self.manager)
            .attach(self.head_info)
    }
}

impl<'r> Responder<'r, 'static> for ScanErrorKind {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        match self {
            Self::ActionNotSupported(_) => Response::build().status(Status::NotImplemented).ok(),
            Self::BadScanStatus { expected, got } => {
                Response::build().status(Status::NotAcceptable).ok()
            }
            Self::ScanAlreadyExists(id) => Response::build().status(Status::Conflict).ok(),
            ScanErrorKind::ScanNotFound(id) => Response::build().status(Status::NotFound).ok(),
            Self::BadRangeFormat(format) => Response::build().status(Status::BadRequest).ok(),
        }
    }
}

#[head("/")]
async fn get_header() -> Status {
    Status::NoContent
}

#[post("/scans", format = "json", data = "<scan>")]
async fn create_scan(
    scan: Json<Scan>,
    manager: &State<Manager>,
) -> Result<Created<Json<ScanID>>, ScanErrorKind> {
    // Mutex
    let mut scan_manager = manager.scan_manager.write().await;

    // Add scan to manager
    let scan_id = scan_manager.create_scan(scan.0)?;

    // Get location of the new data
    let location = uri!("/", get_scan(&scan_id));

    // Generate response
    Ok(Created::new(location.to_string()).body(Json(scan_id)))
}

#[post("/scans/<scan_id>", format = "json", data = "<action>")]
async fn scan_action(
    action: Json<ScanAction>,
    scan_id: String,
    manager: &State<Manager>,
) -> Result<Status, ScanErrorKind> {
    todo!()
}

#[get("/scans/<scan_id>")]
async fn get_scan(scan_id: String, manager: &State<Manager>) -> Result<Json<Scan>, ScanErrorKind> {
    // Mutex
    let scan_manager = manager.scan_manager.read().await;

    // Get Scan from manager
    scan_manager
        .get_scan(scan_id)
        .map(|scan| Json(scan.clone()))
}

#[get("/scans/<scan_id>/results")]
async fn get_results_wo_range(
    scan_id: String,
    manager: &State<Manager>,
) -> Result<Json<Vec<ScanResult>>, ScanErrorKind> {
    get_results(scan_id, None, None, manager).await
}

#[get("/scans/<scan_id>/results?<range>")]
async fn get_results_w_range(
    scan_id: String,
    range: String,
    manager: &State<Manager>,
) -> Result<Json<Vec<ScanResult>>, ScanErrorKind> {
    // Validate range
    // Check for <number>-<number> or <number>
    let (first, last) = match range.split_once("-") {
        // we have two numbers
        Some((x, y)) => (Some(range_parse(x, &range)?), Some(range_parse(y, &range)?)),

        // we only have a single number
        None => match range.parse::<usize>() {
            // try to parse number
            Ok(x) => (Some(x), None),
            Err(_) => return Err(ScanErrorKind::BadRangeFormat(range)),
        },
    };

    get_results(scan_id, first, last, manager).await
}

fn range_parse(x: &str, range: &String) -> Result<usize, ScanErrorKind> {
    match x.parse::<usize>() {
        Ok(y) => Ok(y),
        Err(_) => return Err(ScanErrorKind::BadRangeFormat(range.to_owned())),
    }
}

async fn get_results(
    scan_id: String,
    first: Option<usize>,
    last: Option<usize>,
    manager: &State<Manager>,
) -> Result<Json<Vec<ScanResult>>, ScanErrorKind> {
    // Mutex
    let scan_manager = manager.scan_manager.write().await;

    // Get Results from Scan
    scan_manager
        .get_results(scan_id, first, last)
        .map(|results| Json(results.clone()))
}

#[get("/scans/<scan_id>/status")]
async fn get_status(
    scan_id: String,
    manager: &State<Manager>,
) -> Result<Json<ScanStatus>, ScanErrorKind> {
    // Mutex
    let scan_manager = manager.scan_manager.write().await;

    Ok(Json(scan_manager.get_status(scan_id)?.clone()))
}

#[delete("/scans/<scan_id>")]
async fn delete_scan(scan_id: String, manager: &State<Manager>) -> Result<Status, ScanErrorKind> {
    // Mutex
    let mut scan_manager = manager.scan_manager.write().await;

    // Delete scan
    scan_manager.delete_scan(scan_id)?;
    Ok(Status::Ok)
}

#[get("/vts")]
async fn get_oids(manager: &State<Manager>) -> Json<Vec<String>> {
    // Mutex
    let vt_manager = manager.vt_manager.write().await;

    // Get VTs with query
    Json(vt_manager.get_oids().to_owned())
}
