//! `/vts` routes.
use axum::{
    Router, extract::State, http::status::StatusCode, response::IntoResponse, routing::get,
};

use crate::api::{error::ApiError, response::BodyKind, states::Feed};

/// Access point for all `/vts` prefixed routes.
///
/// Used by [crate::api::router::create_router] to build the HTTP API.
pub fn router(feed: Feed) -> Router {
    Router::new().route("/", get(get_vts)).with_state(feed)
}

/// `GET /vts` route handler.
///
/// Authenticated: no
///
/// Returns a streamed response containing a `JSON` encoded array of `OIDs`.
///
/// ## Errors
/// * 503: feed state is unknown or unsynced
async fn get_vts(State(feed): State<Feed>) -> Result<impl IntoResponse, ApiError> {
    Ok(BodyKind::from_result_stream(StatusCode::OK, feed.get_oids()?).await)
}
