// We allow this fow now, since it would require lots of changes
// but should eventually solve this.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::Path,
    http::{Response, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use scannerlib::notus::{Notus, NotusError, products_loader};
use tokio::sync::RwLock;

use crate::{app::AppState, config::Config};

pub fn config_to_products(config: &Config) -> Arc<RwLock<Notus>> {
    products_loader(&config.notus.products_path, config.feed.signature_check)
}

#[derive(Clone)]
pub struct NotusEndpoints {
    state: Arc<RwLock<Notus>>,
}

impl NotusEndpoints {
    pub fn from_appstate(app_state: &AppState<'_>) -> Self {
        Self {
            state: app_state.notus_state.clone(),
        }
    }

    fn internal_server_error(error: &dyn std::error::Error) -> Response<Body> {
        tracing::warn!(error = %error, "Unexpected error occurred");
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap()
    }

    async fn get_notus_response(&self) -> Response<Body> {
        let products = self.state.clone().read_owned().await;
        match tokio::task::spawn_blocking(move || products.get_available_os())
            .await
            .expect("Tokio runtime must be available")
        {
            Ok(products) => (StatusCode::OK, Json(products)).into_response(),
            Err(error) => Self::internal_server_error(&error),
        }
    }

    async fn post_notus_response(&self, os: String, body: Vec<u8>) -> Response<Body> {
        let products = self.state.clone();

        let packages: Vec<String> = match serde_json::from_slice(&body) {
            Ok(packages) => packages,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap();
            }
        };

        let mut products = products.write_owned().await;
        match tokio::task::spawn_blocking(move || products.scan(&os, &packages))
            .await
            .expect("Tokio runtime must be available")
        {
            Ok(results) => (StatusCode::OK, Json(results)).into_response(),
            Err(NotusError::UnknownProduct(_)) => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap(),
            Err(error) => Self::internal_server_error(&error),
        }
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/notus",
                get({
                    let notus = self.clone();
                    move || async move { notus.get_notus_response().await }
                }),
            )
            .route(
                "/notus/{os}",
                post({
                    let notus = self.clone();
                    move |Path(os): Path<String>, body: axum::body::Bytes| async move {
                        notus.post_notus_response(os, body.to_vec()).await
                    }
                }),
            )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::{NotusEndpoints, config_to_products};
    use crate::config::Config;

    fn config() -> Config {
        let nasl = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/nasl").into();
        let advisories_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/feed/notus/advisories"
        )
        .into();
        let products_path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/notus/products").into();

        let feed = crate::config::Feed {
            path: nasl,
            signature_check: false,
            ..Default::default()
        };
        let notus = crate::config::Notus {
            advisories_path,
            products_path,
            address: None,
        };

        Config {
            feed,
            notus,
            ..Default::default()
        }
    }

    fn router() -> Router {
        let config = config();
        let state = Arc::new(NotusEndpoints {
            state: config_to_products(&config),
        });
        state.router()
    }

    async fn send(router: &Router, request: Request<Body>) -> axum::response::Response {
        router.clone().oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn get_notus() -> crate::Result<()> {
        let resp = send(
            &router(),
            Request::builder()
                .method(Method::GET)
                .uri("/notus")
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn post_notus_os() -> crate::Result<()> {
        let router = router();

        let resp = send(
            &router,
            Request::builder()
                .method(Method::POST)
                .uri("/notus/not_found")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&vec!["aha".to_string()])?))?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = send(
            &router,
            Request::builder()
                .method(Method::POST)
                .uri("/notus/test")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&vec![
                    "man-db-1.1.1".to_string(),
                ])?))?,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        Ok(())
    }
}
