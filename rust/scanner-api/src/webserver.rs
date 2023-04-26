use std::{collections::HashMap, sync::Arc};

use crate::{
    error::APIError,
    scan_manager::{ScanID, ScanManager},
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
    response::status::Created,
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

/// API call to receive the header content on the root path
#[head("/")]
async fn get_header() -> Status {
    Status::NoContent
}

/// API call to create a new scan
#[post("/scans", format = "json", data = "<scan>")]
async fn create_scan(
    scan: Json<Scan>,
    manager: &State<Manager>,
) -> Result<Created<Json<ScanID>>, APIError> {
    // Mutex
    let mut scan_manager = manager.scan_manager.write().await;

    // Add scan to manager
    let scan_id = scan_manager.create_scan(scan.0)?;

    // Get location of the new data
    let location = uri!("/", get_scan(&scan_id));

    // Generate response
    Ok(Created::new(location.to_string()).body(Json(scan_id)))
}

/// API call to perform a action on a scan
#[post("/scans/<scan_id>", format = "json", data = "<action>")]
async fn scan_action(
    action: Json<ScanAction>,
    scan_id: String,
    manager: &State<Manager>,
) -> Result<Status, APIError> {
    let mut scan_manager = manager.scan_manager.write().await;

    scan_manager.scan_action(scan_id, action.action.to_owned())?;

    Ok(Status::NoContent)
}

/// API call to receive information about a requested scan. This does not contain any results or
/// status information, but only meta-information provided by a client with create_scan
#[get("/scans/<scan_id>")]
async fn get_scan(scan_id: String, manager: &State<Manager>) -> Result<Json<Scan>, APIError> {
    // Mutex
    let scan_manager = manager.scan_manager.read().await;

    // Get Scan from manager
    Ok(Json(scan_manager.get_scan(scan_id)?))
}

/// API call to get results without a given range. This will respond with all currently available
/// results
#[get("/scans/<scan_id>/results")]
async fn get_results_wo_range(
    scan_id: String,
    manager: &State<Manager>,
) -> Result<Json<Vec<ScanResult>>, APIError> {
    get_results(scan_id, None, None, manager).await
}

/// API call to get results within a specified range. The range must be of the format
/// <number1>[-<number2>] where number1 >= number2. Both numbers are inclusive Valid ranges are e.g.:
/// - 1
/// - 4-7
/// If only a single number is given, all available results from the specified one are in the
/// response. If a number is out of range of available ones, those results will not be contained
/// in the response and also no error will be shown.
#[get("/scans/<scan_id>/results?<range>")]
async fn get_results_w_range(
    scan_id: String,
    range: String,
    manager: &State<Manager>,
) -> Result<Json<Vec<ScanResult>>, APIError> {
    // Validate range
    // Check for <number1>-<number2> or <number>
    let (first, last) = match range.split_once('-') {
        // we have two numbers
        Some((x, y)) => (Some(range_parse(x, &range)?), Some(range_parse(y, &range)?)),

        // we only have a single number
        None => match range.parse::<usize>() {
            // try to parse number
            Ok(x) => (Some(x), None),
            Err(_) => {
                return Err(APIError::ParseQueryError {
                    message: "Unable to parse range quarry".to_string(),
                    field_errors: HashMap::from([("range".to_string(), format!("The range must be of the format <number1>[-<number2>]. The given quarry {range} is not a number."))]),
                })
            }
        },
    };

    get_results(scan_id, first, last, manager).await
}

/// Helper function to parse a range
/// * `x` - is the actual number to parse
/// * `range` is the complete range string and is used to generate an Error
fn range_parse(x: &str, range: &String) -> Result<usize, APIError> {
    match x.trim().parse::<usize>() {
        Ok(y) => Ok(y),
        Err(_) => Err(APIError::ParseQueryError {
            message: "Unable to parse range quarry".to_string(),
            field_errors: HashMap::from([("range".to_string(), format!("The range must be of the format <number1>[-<number2>]. The given quarry {range} is not a valid range."))]),
        }),
    }
}

/// Function to get the results from a Scan
async fn get_results(
    scan_id: String,
    first: Option<usize>,
    last: Option<usize>,
    manager: &State<Manager>,
) -> Result<Json<Vec<ScanResult>>, APIError> {
    // Mutex
    let scan_manager = manager.scan_manager.write().await;

    // Get Results from Scan
    Ok(Json(scan_manager.get_results(scan_id, first, last)?))
}

/// API call to get information about the Status. In case the scan did not start yes, most of
/// the information is empty.
#[get("/scans/<scan_id>/status")]
async fn get_status(
    scan_id: String,
    manager: &State<Manager>,
) -> Result<Json<ScanStatus>, APIError> {
    // Mutex
    let scan_manager = manager.scan_manager.write().await;

    Ok(Json(scan_manager.get_status(scan_id)?))
}

/// API call to delete a scan. Note that a running scan cannot be deleted and must be stopped before.
#[delete("/scans/<scan_id>")]
async fn delete_scan(scan_id: String, manager: &State<Manager>) -> Result<Status, APIError> {
    // Mutex
    let mut scan_manager = manager.scan_manager.write().await;

    // Delete scan
    scan_manager.delete_scan(scan_id)?;
    Ok(Status::Ok)
}

/// API call to get all available OIDs of the Scanner.
#[get("/vts")]
async fn get_oids(manager: &State<Manager>) -> Json<Vec<String>> {
    // Mutex
    let vt_manager = manager.vt_manager.write().await;

    // Get VTs with query
    Json(vt_manager.get_oids().to_owned())
}
