//! `/vts` routes.
use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;

use crate::api::{error::ApiError, states::Feed, stream::into_json_stream};

/// Access point for all `/vts` prefixed routes.
pub fn router(feed: Feed) -> Router {
    Router::new().route("/", get(get_vts)).with_state(feed)
}

/// URL query parameter for `/vts`
#[derive(Deserialize)]
struct Params {
    information: Option<String>,
}

/// `GET /vts` route handler.
///
/// Authenticated: no
///
/// Returns a streamed response containing a `JSON` encoded array of `OIDs`.
///
/// ## Errors
/// * 503: feed state is unknown or unsynced
async fn get_vts(
    Query(params): Query<Params>,
    State(feed): State<Feed>,
) -> Result<impl IntoResponse, ApiError> {
    if params.information.is_some_and(|x| x == "1" || x == "true") {
        Ok(into_json_stream(feed.get_vts()?).await)
    } else {
        Ok(into_json_stream(feed.get_oids()?).await)
    }
}
