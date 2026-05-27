use std::sync::Arc;

use crate::framework::ClientIdentifier;
use axum::{
    Extension, Router,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use scannerlib::models::FeedState;

use crate::{config::Config, container_image_scanner, scans::ScanState};
use scannerlib::notus::Notus;
use tokio::sync::RwLock;

pub struct AppState<'a> {
    pub feed_state: Arc<std::sync::RwLock<FeedState>>,
    pub config: &'a Config,
    pub scan_state: Arc<ScanState>,
    pub cis_scan_state: Arc<container_image_scanner::endpoints::scans::ScanState>,
    pub notus_state: Arc<RwLock<Notus>>,
}

#[derive(Clone)]
pub struct HealthHeaders {
    authentication: &'static str,
    api_version: &'static str,
    feed_state: Arc<std::sync::RwLock<FeedState>>,
}

impl HealthHeaders {
    pub fn from_appstate(app_state: &AppState<'_>) -> Self {
        Self {
            authentication: if app_state.config.tls.client_certs.is_some() {
                "mTLS"
            } else if app_state.config.endpoints.key.is_some() {
                "api-key"
            } else {
                "disabled"
            },
            api_version: "1",
            feed_state: app_state.feed_state.clone(),
        }
    }

    pub fn feed_version(&self) -> String {
        match &(*self.feed_state.read().unwrap()) {
            FeedState::Unknown => "unknown".to_uppercase(),
            FeedState::Syncing => "syncing".to_uppercase(),
            FeedState::Synced(nasl, notus) => format!("{nasl}::{notus}"),
        }
    }

    pub fn apply_to_response<T>(&self, response: &mut Response<T>) {
        response.headers_mut().insert(
            "authentication",
            HeaderValue::from_static(self.authentication),
        );
        response
            .headers_mut()
            .insert("api-version", HeaderValue::from_static(self.api_version));
        response.headers_mut().insert(
            "feed-version",
            HeaderValue::from_str(&self.feed_version())
                .unwrap_or(HeaderValue::from_static("unavailable")),
        );
    }

    pub fn ready_response(&self, ident: ClientIdentifier) -> Response {
        tracing::info!(?ident, "health ready requested");

        let status = match *self.feed_state.read().unwrap() {
            FeedState::Unknown | FeedState::Syncing => StatusCode::SERVICE_UNAVAILABLE,
            FeedState::Synced(_, _) => StatusCode::OK,
        };

        status.into_response()
    }

    fn ok_route(&self) -> axum::routing::MethodRouter {
        get(move || async move { StatusCode::OK.into_response() })
            .head(move || async move { StatusCode::OK.into_response() })
    }

    fn ready_route(&self) -> axum::routing::MethodRouter {
        get({
            let headers = self.clone();
            move |Extension(ident): Extension<ClientIdentifier>| async move {
                headers.ready_response(ident)
            }
        })
        .head({
            let headers = self.clone();
            move |Extension(ident): Extension<ClientIdentifier>| async move {
                headers.ready_response(ident)
            }
        })
    }

    fn routes(&self) -> Router {
        Router::new()
            .route("/health", self.ready_route())
            .route("/health/alive", self.ok_route())
            .route("/health/ready", self.ready_route())
            .route("/health/started", self.ok_route())
    }

    pub fn router(&self, prefix: &'static str) -> Router {
        let router = self.routes();

        if prefix.is_empty() {
            router
        } else {
            Router::new().nest(prefix, router)
        }
    }
}
