//! `/vts` routes.
use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;

use crate::api::{error::ApiError, states::Feed, stream::into_json_stream};

/// Access point for all vts routes.
pub fn router(feed: Feed) -> Router {
    Router::new()
        .route("/vts", get(get_vts))
        .route("/container-image-scanner/vts", get(get_vts))
        .with_state(feed)
}

/// URL query parameter for `/vts` and `/container-image-scanner/vts`
#[derive(Deserialize)]
pub(super) struct Params {
    pub(super) information: Option<String>,
}

/// `GET /vts` and `GET /container-image-scanner/vts` route handler.
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
