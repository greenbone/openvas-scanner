//! `/container-image-scanner` routes.
#![allow(clippy::result_large_err)]

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State, rejection::JsonRejection},
    http::status::StatusCode,
    response::IntoResponse,
    routing::{delete, get, head, post},
};
use serde::Deserialize;

use std::sync::Arc;

use crate::api::{
    Authentication,
    auth::{AuthLayer, ClientId},
    error::ApiError,
    response::BodyKind,
    states::ScannerBridge,
};
use scannerlib::models::{self, PreferenceValue, ScanPreferenceInformation};

const PREFERENCES: [ScanPreferenceInformation; 2] = [
    ScanPreferenceInformation {
        id: "accept_invalid_certs",
        name: "Accepts certificates without trust chain verification",
        default: PreferenceValue::Bool(true),
        description: "This disables the CA chain verification for TLS certificates when connecting to a registry. \
                    This is useful for self-signed certificates.",
    },
    ScanPreferenceInformation {
        id: "registry_allow_insecure",
        name: "Use HTTP instead of HTTPS",
        default: PreferenceValue::Bool(false),
        description: "This allows unencrypted communication with an registry (HTTP instead of HTTPS).",
    },
];

/// Access point for all `/container-image-scanner` prefixed routes.
///
/// Used by [crate::api::router::create_router] to build the HTTP API.
pub fn router(
    scanner: ScannerBridge,
    auth_method: Authentication,
    api_keys: Arc<Vec<String>>,
    enable_additional_routes: bool,
) -> Router {
    Router::new()
        .route(
            "/",
            if enable_additional_routes {
                // HEAD routes are auto generated from their GET counterpart
                get(get_scans)
            } else {
                // add an explicit HEAD route if the GET route is disabled
                head(())
            },
        )
        .route("/", post(post_scans))
        .route("/preferences", get(get_scans_preferences))
        .route("/{id}", get(get_scans_id))
        .route("/{id}", post(post_scans_id))
        .route("/{id}", delete(delete_scans_id))
        .route("/{id}/results", get(get_scans_id_results))
        .route("/{id}/results/{rid}", get(get_scans_id_results_rid))
        .route("/{id}/status", get(get_scans_id_status))
        // enable authentication for all routes
        .layer(AuthLayer::new(auth_method, api_keys))
        .with_state(scanner)
}

/// `GET /container-image-scanner/scans/preferences` route handler
///
/// Authenticated: yes
///
/// Returns `JSON` encoded list of all available scan preferences, which can be set within the scan
/// configuration via the POST /scans endpoint.
///
/// ## Errors
/// * 401: unauthorized access
async fn get_scans_preferences() -> impl IntoResponse {
    axum::Json::from(PREFERENCES)
}

/// `GET /container-image-scanner/scans` route handler
///
/// Authenticated: yes
///
/// Returns a `JSON` encoded list of all scans belonging to the users client ID.
/// All passwords are redacted and it contains no status or result information.
///
/// ## Errors
/// * 401: unauthorized access
/// * 405: `enable_get_scans` is set to false
/// * 500: internal error
async fn get_scans(
    client_id: Extension<ClientId>,
    State(scanner): State<ScannerBridge>,
) -> impl IntoResponse {
    BodyKind::from_result_stream(
        StatusCode::OK,
        scanner.get_scans(client_id.to_string()).await,
    )
    .await
}

/// `POST /container-image-scanner/scans` route handler
///
/// Authenticated: yes
///
/// Creates a new `scan` with a given `JSON` encoded configuration without starting it. On success
/// the `id` of the newly created scan is returned with a `201 CREATED` status code.
///
/// ## Errors
/// * 400: invalid scan configuration
/// * 401: unauthorized access
/// * 409: a scan with the same `id` already exists
async fn post_scans(
    client_id: Extension<ClientId>,
    State(scanner): State<ScannerBridge>,
    scan: Result<Json<models::Scan>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let mut scan = scan?;

    // generate a random scan id if none was given
    if scan.scan_id.is_empty() {
        scan.scan_id = uuid::Uuid::new_v4().into();
    }

    scanner.post_scan(&client_id, &scan).await?;
    Ok((StatusCode::CREATED, Json(scan.scan_id.clone())).into_response())
}

/// `GET /container-image-scanner/scans/{id}` route handler
///
/// Authenticated: yes
///
/// Provides `JSON` encoded information about a scan with a given `id` previously added by `POST /container-image-scanner/scans`.
/// All passwords are redacted and it contains no status or result information.
///
/// ## Errors
/// * 401: unauthorized access
/// * 404: scan not found
async fn get_scans_id(
    client_id: Extension<ClientId>,
    Path(scan_id): Path<String>,
    State(scanner): State<ScannerBridge>,
) -> Result<impl IntoResponse, ApiError> {
    let mut scan = scanner.get_scan(&client_id, &scan_id).await?;

    // hide passwords from the credentials
    scan.target.credentials = scan
        .clone()
        .target
        .credentials
        .into_iter()
        .map(|c| c.hide_pass())
        .collect();

    Ok(Json(scan))
}

/// `POST /container-image-scanner/scans/{id}` route handler
///
/// Authenticated: yes
///
/// Performs an action on a scan, either starting or stopping it, that was previously stored by the user.
/// Returns an empty response with the status code `204 NO CONTENT`.
///
/// ## Schema
/// ```json
///{
///  "action": "stop|start"
///}
/// ```
///
/// ## Errors
/// * 400: invalid action user input
/// * 401: unauthorized access
/// * 500: internal error
async fn post_scans_id(
    client_id: Extension<ClientId>,
    Path(scan_id): Path<String>,
    State(scanner): State<ScannerBridge>,
    action: Result<Json<models::ScanAction>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    scanner
        .schedule_scan(&client_id, &scan_id, action?.action)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /container-image-scanner/scans/{id}` route handler
///
/// Authenticated: yes
///
/// Deletes a scan with a given ID. The scan cannot be deleted when it is currently running.
/// The current status can be retrieved via `GET /container-image-scanner/scans/{id}/status`.
///
/// On success an empty response with the status code `204 NO CONTENT` is returned.
///
/// ## Errors
/// * 401: unauthorized access
/// * 404: scan not found
/// * 409: scan is currently running
/// * 500: internal error
async fn delete_scans_id(
    client_id: Extension<ClientId>,
    Path(scan_id): Path<String>,
    State(scanner): State<ScannerBridge>,
) -> Result<impl IntoResponse, ApiError> {
    let status = scanner.get_scan_status(&client_id, &scan_id).await?;

    // scan is not running
    if !status.is_running() {
        scanner.delete_scan(&client_id, &scan_id).await?;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::ScanRunning)
    }
}

/// URL query parameter for /scans/{id}/results
#[derive(Deserialize)]
pub struct Params {
    range: Option<String>,
}

/// `GET /container-image-scanner/scans/{id}/results` route handler
///
/// Authenticated: yes
///
/// Retrieves the results of a scan. If the scan is still running partial results are returned as
/// they are being generated.
///
/// The results can be filtered using the `range` query by specifying a range or just a single
/// result index, for example range=3 or range=1-3
///
/// ## Errors
/// * 400: invalid range format
/// * 401: unauthorized access
/// * 404: scan not found
async fn get_scans_id_results(
    client_id: Extension<ClientId>,
    Path(scan_id): Path<String>,
    Query(params): Query<Params>,
    State(scanner): State<ScannerBridge>,
) -> Result<impl IntoResponse, ApiError> {
    let range = params
        .range
        .map(|x| super::scans::parse_results_range(&x))
        .transpose()?;

    let results = scanner
        .get_scan_results(
            &client_id,
            &scan_id,
            range.map(|(x, _)| x),
            range.map(|(_, x)| x),
        )
        .await?;

    Ok(BodyKind::from_result_stream(StatusCode::OK, results).await)
}

/// `GET /container-image-scanner/scans/{id}/results/{rid}` route handler
///
/// Authenticated: yes
///
/// Retrieves a single specified `JSON` encoded result of a given scan.
///
/// ## Errors
/// * 400: invalid ID
/// * 401: unauthorized access
/// * 404: scan not found
pub async fn get_scans_id_results_rid(
    client_id: Extension<ClientId>,
    Path((scan_id, result_id)): Path<(String, usize)>,
    State(scanner): State<ScannerBridge>,
) -> Result<impl IntoResponse, ApiError> {
    let result = scanner
        .get_scan_result(&client_id, &scan_id, result_id)
        .await?;
    Ok(Json(result))
}

/// `GET /container-image-scanner/scans/{id}/status` route handler
///
/// Authenticated: yes
///
/// Provides `JSON` encoded status information about a scan with a given `id` previously added by
/// `POST /container-image/scanner/scans`.
///
/// ## Schema
/// ```json
/// {
///   "start_time": 0,
///   "end_time": 0,
///   "status": "stored",
///   "host_info": {
///     "all": 0,
///     "excluded": 0,
///     "dead": 0,
///     "alive": 0,
///     "queued": 0,
///     "finished": 0
///   }
/// }
/// ```
///
/// ## Errors
/// * 401: unauthorized access
/// * 404: scan couldn't be found
async fn get_scans_id_status(
    client_id: Extension<ClientId>,
    Path(scan_id): Path<String>,
    State(scanner): State<ScannerBridge>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(scanner.get_scan_status(&client_id, &scan_id).await?))
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc};

    use crate::{
        Config,
        api::{
            ApiConfig, Authentication,
            tests::{json_request, send_request},
        },
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http::HeaderValue;
    use http_body_util::BodyExt;
    use scannerlib::models::Scan;

    async fn config() -> anyhow::Result<ApiConfig> {
        let cfg = Config::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("data/tests/scanner/config/basic.toml"),
        );
        crate::init_api(cfg).await
    }

    /// Tests that all /container-image-scanner prefixed routes require authentication.
    /// All requests are relative from the /container-image-scanner prefix.
    #[tokio::test]
    async fn scan_routes_unauth() -> anyhow::Result<()> {
        let cfg = config().await?;
        let mut router = super::router(
            cfg.scanner,
            Authentication::ApiKey,
            Arc::new(vec!["secret".to_string()]),
            true,
        )
        .into_service();

        // Authentication precedes the validation of the individual route input data, making them
        // irrelevant for the sake of this test.
        //
        // The current implementation applies the authentication layer to the whole router which
        // enforces authentication to ALL routes, but since this is security related and the
        // implementation might change in the future each route is tested explicitly.
        let req = Request::get("/").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::post("/").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::get("/preferences").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::get("/s1").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::post("/s1").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::delete("/s1").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::get("/s1/results").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::get("/s1/results/r1").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::get("/s1/status").body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    /// Tests api-key authentication
    #[tokio::test]
    async fn scan_routes_api_key_authentication() -> anyhow::Result<()> {
        let cfg = config().await?;
        let mut router = super::router(
            cfg.scanner,
            Authentication::ApiKey,
            Arc::new(vec!["secret1".to_string(), "secret2".to_string()]),
            true,
        )
        .into_service();

        let req = Request::get("/")
            .header("X-Api-Key", "secret1")
            .body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = Request::get("/")
            .header("X-Api-Key", "secret2")
            .body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = Request::get("/")
            .header("X-Api-Key", "invalid")
            .body(Body::empty())?;
        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    /// Tests client data separation for the GET /container-image-scanner/scan route
    #[tokio::test]
    async fn get_scans_client_separation() -> anyhow::Result<()> {
        let cfg = config().await?;
        let mut router = super::router(
            cfg.scanner,
            Authentication::ApiKey,
            Arc::new(vec!["client1".to_string(), "client2".to_string()]),
            true,
        )
        .into_service();

        let scan1 = Scan {
            scan_id: "scan1".to_string(),
            ..Default::default()
        };

        // Since the request is router relative the real API url is POST /container-image-scanner/scans
        let mut req = json_request("POST", "/", &scan1);
        req.headers_mut()
            .insert("X-Api-Key", HeaderValue::from_static("client1"));

        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let scan2 = Scan {
            scan_id: "scan2".to_string(),
            ..Default::default()
        };

        // Since the request is router relative the real API url is POST /container-image-scanner/scans
        let mut req = json_request("POST", "/", &scan2);
        req.headers_mut()
            .insert("X-Api-Key", HeaderValue::from_static("client2"));

        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Get client1s scans, again route relative
        let req = Request::get("/")
            .header("X-Api-Key", "client1")
            .body(Body::empty())?;

        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = resp.into_body().collect().await?.to_bytes();
        let client1_scans: Vec<&str> = serde_json::from_slice(&bytes)?;

        // Must only return the scan added by client1
        assert_eq!(&client1_scans, &["scan1"]);

        // Get client2s scans, again route relative
        let req = Request::get("/")
            .header("X-Api-Key", "client2")
            .body(Body::empty())?;

        let resp = send_request(&mut router, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = resp.into_body().collect().await?.to_bytes();
        let client1_scans: Vec<&str> = serde_json::from_slice(&bytes)?;

        // Must only return the scan added by client2
        assert_eq!(&client1_scans, &["scan2"]);

        Ok(())
    }
}
