//! `/notus` routes.
use axum::{
    Json, Router,
    extract::{Path, State, rejection::JsonRejection},
    response::IntoResponse,
    routing::{get, post},
};
use scannerlib::notus::Notus;
use tokio::sync::RwLock;

use std::sync::Arc;

use crate::api::error::ApiError;

/// Access point for all `/notus` prefixed routes.
///
/// Used by [crate::api::router::create_router] to build the HTTP API.
pub fn router(notus: Arc<RwLock<Notus>>) -> Router {
    Router::new()
        .route("/", get(get_notus))
        .route("/{os}", post(post_notus))
        .with_state(notus)
}

/// GET /notus route handler
///
/// Authenticated: no
///
/// Returns a `JSON` encoded array of all supported operating systems.
///
/// ## Errors
/// * 500: internal error
async fn get_notus(
    State(notus): State<Arc<RwLock<scannerlib::notus::Notus>>>,
) -> Result<impl IntoResponse, ApiError> {
    let result = notus.read_owned().await.get_available_os()?;
    Ok(Json(result))
}

/// POST /notus/{os} route handler
///
/// Authenticated: no
///
/// Compares a given `JSON` encoded array of packages on a given OS against a list of known vulnerabilities.
/// On success a `JSON` encoded list of all vulnerable packages along with their fixed versions is returned.
///
/// ## Errors
/// * 400: invalid `JSON` input data
/// * 404: unknown OS
/// * 500: internal error
async fn post_notus(
    Path(os): Path<String>,
    State(notus): State<Arc<RwLock<scannerlib::notus::Notus>>>,
    packages: Result<Json<Vec<String>>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let mut notus = notus.write_owned().await;

    let result = notus.scan(&os, &packages?)?;
    Ok(Json(result))
}
