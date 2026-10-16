//! `/health` routes.
use std::sync::Arc;

use tokio::process::Command;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::{get, head},
};
use regex::Regex;
use serde::Deserialize;

use crate::api::{Authentication, auth::AuthLayer, error::ApiError};

const PERFORMANCE_TITLES: &str = r"(cpu-.*)|(proc)|(mem)|(swap)|(load)|(df-.*)|(disk-sd[a-z][0-9]-rw)|(disk-sd[a-z][0-9]-load)|(disk-sd[a-z][0-9]-io-load)|(interface-eth.*-traffic)|(interface-eth.*-err-rate)|(interface-eth.*-err)|(sensors-.*_temperature-.*)|(sensors-.*_fanspeed-.*)|(sensors-.*_voltage-.*)|(titles)";
const PERFORMANCE_TITLES_FORBIDDEN: &str = r"^[^|&;]+$";

#[derive(Debug, Clone)]
struct RegState {
    titles: Regex,
    forbidden: Regex,
}

/// Access point for `/performance` prefixed route.
pub fn router(auth_method: Authentication, api_keys: Arc<Vec<String>>) -> Router {
    let state = RegState {
        titles: Regex::new(PERFORMANCE_TITLES).unwrap(),
        forbidden: Regex::new(PERFORMANCE_TITLES_FORBIDDEN).unwrap(),
    };

    // only the performance route requires authentication
    let performance = Router::new()
        .route("/performance", get(get_performance))
        .layer(AuthLayer::new(auth_method, api_keys))
        .with_state(state);

    Router::new()
        .route("/", head(()))
        .route("/alive", get(()))
        .route("/ready", get(()))
        .route("/started", get(()))
        .merge(performance)
}

/// URL query parameter for `/health/performance`
#[derive(Deserialize, Debug)]
struct Titles {
    titles: String,
    start: Option<i64>,
    end: Option<i64>,
}

/// `GET /health/performance` route handler.
///
/// Authenticated: yes
///
/// Returns a streamed response containing a `JSON` encoded array of `OIDs`.
///
/// ## Errors
/// * 400: Bad Bogus request
/// * 500: Command not found or invalid permission
async fn get_performance(
    Query(query): Query<Titles>,
    State(state): State<RegState>,
) -> Result<impl IntoResponse, ApiError> {
    let mut child = Command::new("gvmcg");

    if !state.titles.is_match(&query.titles) || !state.forbidden.is_match(&query.titles) {
        return Err(ApiError::InvalidInput(
            "Bogus GET performance format. Argument not allowed".to_string(),
        ));
    };

    if let Some(s) = query.start {
        child.arg(format!("{s}"));
    }
    if let Some(e) = query.end {
        child.arg(format!("{e}"));
    }

    let child = child.arg(query.titles).output();
    match child.await {
        Ok(output) if output.status.success() => {
            let text_base64 = vec![String::from_utf8_lossy(&output.stdout).replace('\n', "")];
            Ok(Json(text_base64))
        }
        Ok(output) => Err(ApiError::InvalidInput(
            str::from_utf8(&output.stderr).unwrap().to_string(),
        )),
        Err(output) => Err(ApiError::UnavailableCmd(output.to_string())),
    }
}
