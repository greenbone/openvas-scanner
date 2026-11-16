//! `/health` routes.
use tokio::process::Command;

use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, head},
};
use regex::Regex;
use serde::Deserialize;

use crate::api::error::ApiError;

const PERFORMANCE_TITLES: &str = r"(cpu-.*)|(proc)|(mem)|(swap)|(load)|(df-.*)|(disk-sd[a-z][0-9]-rw)|(disk-sd[a-z][0-9]-load)|(disk-sd[a-z][0-9]-io-load)|(interface-eth.*-traffic)|(interface-eth.*-err-rate)|(interface-eth.*-err)|(sensors-.*_temperature-.*)|(sensors-.*_fanspeed-.*)|(sensors-.*_voltage-.*)|(titles)";
const PERFORMANCE_TITLES_FORBIDDEN: &str = r"^[^|&;]+$";

/// Access point for `/performance` prefixed route.
pub fn router() -> Router {
    Router::new()
        .route("/", head(()))
        .route("/alive", get(()))
        .route("/ready", get(()))
        .route("/started", get(()))
        .route("/performance", get(get_performance))
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
/// Authenticated: no
///
/// Returns a streamed response containing a `JSON` encoded array of `OIDs`.
///
/// ## Errors
/// * 400: Bad Bogus request
/// * 500: Command not found or invalid permission
async fn get_performance(Query(query): Query<Titles>) -> Result<impl IntoResponse, ApiError> {
    let mut child = Command::new("gvmcg");
    let re_titles = Regex::new(PERFORMANCE_TITLES).unwrap();
    let re_forbidden = Regex::new(PERFORMANCE_TITLES_FORBIDDEN).unwrap();

    if !re_titles.is_match(&query.titles) || !re_forbidden.is_match(&query.titles) {
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
