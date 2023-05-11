// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;

use crate::{
    error::APIError, guards::json_validation::JsonValidation, manager::ScanID, webserver::Manager,
};
use models::{Result as ScanResult, Scan, ScanAction, Status as ScanStatus};
use rocket::{
    delete, get, head, http::Status, post, response::status::Created, serde::json::Json, uri, State,
};

/// API call to receive the header content on the root path
#[head("/")]
pub async fn get_header() -> Status {
    Status::NoContent
}

/// API call to create a new scan
#[post("/scans", format = "json", data = "<scan>")]
pub async fn create_scan(
    scan: JsonValidation<Scan>,
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
pub async fn scan_action(
    action: JsonValidation<ScanAction>,
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
pub async fn get_scan(scan_id: String, manager: &State<Manager>) -> Result<Json<Scan>, APIError> {
    // Mutex
    let scan_manager = manager.scan_manager.read().await;

    // Get Scan from manager
    Ok(Json(scan_manager.get_scan(scan_id)?))
}

/// API call to get results without a given range. This will respond with all currently available
/// results
#[get("/scans/<scan_id>/results")]
pub async fn get_results_wo_range(
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
pub async fn get_results_w_range(
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
pub async fn get_results(
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
pub async fn get_status(
    scan_id: String,
    manager: &State<Manager>,
) -> Result<Json<ScanStatus>, APIError> {
    // Mutex
    let scan_manager = manager.scan_manager.write().await;

    Ok(Json(scan_manager.get_status(scan_id)?))
}

/// API call to delete a scan. Note that a running scan cannot be deleted and must be stopped before.
#[delete("/scans/<scan_id>")]
pub async fn delete_scan(scan_id: String, manager: &State<Manager>) -> Result<Status, APIError> {
    // Mutex
    let mut scan_manager = manager.scan_manager.write().await;

    // Delete scan
    scan_manager.delete_scan(scan_id)?;
    Ok(Status::Ok)
}

/// API call to get all available OIDs of the Scanner.
#[get("/vts")]
pub async fn get_oids(manager: &State<Manager>) -> Json<Vec<String>> {
    // Mutex
    let vt_manager = manager.vt_manager.write().await;

    // Get VTs with query
    Json(vt_manager.get_oids().to_owned())
}
