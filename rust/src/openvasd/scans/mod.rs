use std::sync::Arc;

use crate::framework::{
    GetScansError, GetScansIDResultsIDError, PostScansError, PostScansIDError, StreamResult,
};
use axum::Router;
use futures::TryStreamExt;
use scannerlib::{PromiseRef, models, scanner};
use tokio::sync::mpsc::Sender;

use crate::database::{
    dao::{Execute, Fetch, StreamFetch},
    sqlite::{DataBase, results::DBResults, scans::ScanDB},
};

use crate::{
    app::AppState,
    config::Config,
    credentials,
    crypt::ChaCha20Crypt,
    framework,
    scan_routes::{ScanBackend, ScanRoutes},
    vts::orchestrator,
};
pub(crate) mod scheduling;

#[derive(Clone)]
pub(crate) struct ScanState {
    pool: DataBase,
    crypter: Arc<ChaCha20Crypt>,
    scheduling: Sender<scheduling::Message>,
}

#[derive(Clone)]
pub(crate) struct Scans {
    state: Arc<ScanState>,
}

pub(crate) fn config_to_crypt(config: &Config) -> ChaCha20Crypt {
    // unwrap_or_else is a safe guard in the case the db is stored on disk but no key is provided.
    // Otherwise the credentials can never be decrypted.
    credentials::config_to_crypt(config.storage.credential_key())
}

pub async fn init(
    pool: DataBase,
    config: &Config,
    feed_status: orchestrator::Communicator,
) -> Result<ScanState, Box<dyn std::error::Error + Send + Sync>> {
    let crypter = Arc::new(config_to_crypt(config));
    let scheduler_sender =
        scheduling::init(pool.clone(), crypter.clone(), config, feed_status).await?;
    Ok(ScanState {
        pool,
        crypter,
        scheduling: scheduler_sender,
    })
}

impl ScanState {
    pub(crate) fn pool(&self) -> DataBase {
        self.pool.clone()
    }
}

impl Scans {
    pub(crate) fn from_appstate(app_state: &AppState<'_>) -> Self {
        Self {
            state: app_state.scan_state.clone(),
        }
    }

    async fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Result<String, PostScansError> {
        framework::map_post_scan_result(
            ScanDB::new(
                &self.state.pool,
                (self.state.crypter.as_ref(), client_id.as_str(), &scan),
            )
            .exec()
            .await,
            scan.scan_id,
        )
    }

    async fn contains_scan_id(&self, client_id: &str, scan_id: &str) -> Option<String> {
        framework::map_contains_scan_id(
            ScanDB::new(&self.state.pool, (client_id, scan_id))
                .fetch()
                .await,
        )
    }
    pub(crate) fn router(&self) -> Router {
        ScanRoutes::new(self.clone(), "").router()
    }
}

impl ScanBackend for Scans {
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> PromiseRef<'_, Result<String, PostScansError>> {
        Box::pin(async move { Scans::post_scans(self, client_id, scan).await })
    }

    fn contains_scan_id<'a>(
        &'a self,
        client_id: &'a str,
        scan_id: &'a str,
    ) -> PromiseRef<'a, Option<String>> {
        Box::pin(async move { Scans::contains_scan_id(self, client_id, scan_id).await })
    }

    fn get_scans(&self, client_id: String) -> StreamResult<String, GetScansError> {
        Box::pin(
            ScanDB::new(&self.state.pool, client_id)
                .stream_fetch()
                .map_err(framework::into_get_scans_error),
        )
    }

    fn get_scans_preferences(&self) -> PromiseRef<'_, Vec<models::ScanPreferenceInformation>> {
        Box::pin(async move { scanner::preferences::preference::PREFERENCES.to_vec() })
    }

    fn get_scans_id(&self, id: String) -> PromiseRef<'_, Result<models::Scan, GetScansError>> {
        Box::pin(async move {
            let id = id.parse().map_err(GetScansError::from_external)?;
            ScanDB::new(&self.state.pool, (self.state.crypter.as_ref(), id))
                .fetch()
                .await
                .map_err(framework::into_get_scans_error)
        })
    }

    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<models::Result, GetScansError> {
        Box::pin(
            DBResults::new(&self.state.pool, (id, from, to))
                .stream_fetch()
                .map_err(GetScansError::from_external),
        )
    }

    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> PromiseRef<'_, Result<models::Result, GetScansIDResultsIDError>> {
        Box::pin(async move {
            framework::map_result_id_fetch(
                DBResults::new(&self.state.pool, (id, result_id))
                    .fetch()
                    .await,
            )
        })
    }

    fn get_scans_id_status(
        &self,
        id: String,
    ) -> PromiseRef<'_, Result<models::Status, GetScansError>> {
        Box::pin(async move {
            let id: i64 = id.parse().map_err(GetScansError::from_external)?;
            ScanDB::new(&self.state.pool, id)
                .fetch()
                .await
                .map_err(GetScansError::from_external)
        })
    }

    fn post_scans_id(
        &self,
        id: String,
        action: models::Action,
    ) -> PromiseRef<'_, Result<(), PostScansIDError>> {
        Box::pin(async move {
            let status =
                self.get_scans_id_status(id.clone())
                    .await
                    .map_err(|error| match error {
                        GetScansError::NotFound => PostScansIDError::External(Box::new(
                            std::io::Error::new(std::io::ErrorKind::NotFound, "scan not found"),
                        )),
                        GetScansError::External(error) => PostScansIDError::External(error),
                    })?;
            let message = match (action, status.status) {
                (models::Action::Start, models::Phase::Stored | models::Phase::Stopped) => {
                    Ok(scheduling::Message::Start(id))
                }
                (models::Action::Stop, models::Phase::Running) => Ok(scheduling::Message::Stop(id)),
                _ => Err(PostScansIDError::Running),
            }?;

            self.state
                .scheduling
                .send(message)
                .await
                .map_err(|e| PostScansIDError::External(Box::new(e)))
        })
    }

    fn delete_scans_id(&self, id: String) -> PromiseRef<'_, Result<(), PostScansIDError>> {
        Box::pin(async move {
            ScanDB::new(&self.state.pool, id)
                .exec()
                .await
                .map_err(PostScansIDError::from_external)
                .map(|_| ())
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::framework::{ClientHash, ClientIdentifier};
    use axum::{
        Extension, Router,
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use scannerlib::models;
    use serde::de::DeserializeOwned;
    use sqlx::{SqlitePool, query_scalar};
    use tower::ServiceExt;

    use super::{ScanState, Scans};
    use crate::{
        config::Config,
        container_image_scanner::config::DBLocation,
        database::dao::Execute,
        database::sqlite::{results::DBResults, scans::ScanDB},
    };

    pub(crate) async fn create_pool() -> crate::Result<(Config, SqlitePool)> {
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
            ..Default::default()
        };
        let notus = crate::config::Notus {
            advisories_path,
            products_path,
            address: None,
        };
        let scanner = crate::config::Scanner {
            scanner_type: crate::config::ScannerType::Openvasd,
            ..Default::default()
        };
        let scheduler = crate::config::Scheduler {
            check_interval: Duration::from_micros(10),
            ..Default::default()
        };

        let config = Config {
            feed,
            notus,
            scanner,
            scheduler,
            container_image_scanner: crate::container_image_scanner::config::Config {
                database: crate::container_image_scanner::config::SqliteConfiguration {
                    location: DBLocation::InMemory,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let pool = crate::setup_sqlite(&config).await?;
        Ok((config, pool))
    }

    pub(crate) async fn prepare_scans(pool: SqlitePool, config: &Config) -> Vec<i64> {
        let client_id = "moep".to_string();
        let scans = [sample_scan("prepared-1"), sample_scan("prepared-2")];
        let crypter = super::config_to_crypt(config);
        let mut ids = Vec::new();

        for scan in scans {
            ScanDB::new(&pool, (&crypter, client_id.as_str(), &scan))
                .exec()
                .await
                .unwrap();
            let id = query_scalar("SELECT id FROM client_scan_map WHERE scan_id = ?")
                .bind(&scan.scan_id)
                .fetch_one(&pool)
                .await
                .unwrap();
            ids.push(id);
        }

        ids
    }

    async fn create_scan_state() -> crate::Result<Arc<ScanState>> {
        let (config, pool) = create_pool().await?;
        Ok(Arc::new(
            super::init(pool, &config, Default::default()).await?,
        ))
    }

    fn router(state: Arc<ScanState>, ident: ClientIdentifier) -> Router {
        Scans { state }.router().layer(Extension(ident))
    }

    fn known_ident() -> ClientIdentifier {
        ClientIdentifier::Known(ClientHash::default())
    }

    fn other_ident() -> ClientIdentifier {
        ClientIdentifier::Known(ClientHash::from("other-user"))
    }

    fn sample_scan(scan_id: &str) -> models::Scan {
        let mut scan: models::Scan = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/discovery.json"
        )))
        .unwrap();
        scan.scan_id = scan_id.to_string();
        scan
    }

    async fn send(router: &Router, request: Request<Body>) -> axum::response::Response {
        router.clone().oneshot(request).await.unwrap()
    }

    async fn body_json<T: DeserializeOwned>(response: axum::response::Response) -> T {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn scan_status(router: &Router, scan_id: &str) -> crate::Result<serde_json::Value> {
        let response = send(
            router,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{scan_id}/status"))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(body_json(response).await)
    }

    async fn wait_for_scan_phase(
        router: &Router,
        scan_id: &str,
        phase: models::Phase,
        timeout: Duration,
    ) -> crate::Result<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let status = scan_status(router, scan_id).await?;
            let current = status
                .get("status")
                .and_then(|v| v.as_str())
                .ok_or_else(|| std::io::Error::other("missing status field"))?
                .parse::<models::Phase>()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            if current == phase {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "scan {scan_id} did not reach phase {:?} within {:?}, last phase: {:?}",
                    phase, timeout, current
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn insert_results(pool: &SqlitePool, external_scan_id: &str) -> crate::Result<()> {
        let internal_id: i64 = query_scalar("SELECT id FROM client_scan_map WHERE scan_id = ?")
            .bind(external_scan_id)
            .fetch_one(pool)
            .await?;
        let internal_id = internal_id.to_string();

        let results = vec![
            models::Result {
                message: Some("first".to_string()),
                ..Default::default()
            },
            models::Result {
                message: Some("second".to_string()),
                ..Default::default()
            },
            models::Result {
                message: Some("third".to_string()),
                ..Default::default()
            },
        ];

        DBResults::new(pool, (internal_id.as_str(), results.as_slice()))
            .exec()
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn post_list_and_get_scan_via_http() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, known_ident());
        let scan = sample_scan("scan-http-roundtrip");

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let created_id: String = body_json(response).await;
        assert_eq!(created_id, scan.scan_id);

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri("/scans")
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let scan_ids: Vec<String> = body_json(response).await;
        assert!(scan_ids.contains(&scan.scan_id));

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let returned_scan: models::Scan = body_json(response).await;
        assert_eq!(returned_scan.scan_id, scan.scan_id);

        Ok(())
    }

    #[tokio::test]
    async fn unauthenticated_requests_are_rejected() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, ClientIdentifier::Unknown);

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri("/scans")
                .body(Body::empty())?,
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_scan_id_is_rejected_via_http() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, known_ident());
        let scan = sample_scan("scan-duplicate");
        let body = serde_json::to_vec(&scan)?;

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(body))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        Ok(())
    }

    #[tokio::test]
    async fn scan_preferences_are_available_via_http() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, known_ident());

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri("/scans/preferences")
                .body(Body::empty())?,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let preferences: serde_json::Value = body_json(response).await;
        assert!(preferences.as_array().is_some_and(|x| !x.is_empty()));
        Ok(())
    }

    #[tokio::test]
    async fn foreign_client_cannot_access_other_clients_scan() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let owner_app = router(state.clone(), known_ident());
        let other_app = router(state, other_ident());
        let scan = sample_scan("scan-owner-only");

        let response = send(
            &owner_app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            &other_app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_result_id_returns_bad_request() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, known_ident());
        let scan = sample_scan("scan-invalid-result-id");

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}/results/not-a-number", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn get_results_ranges_via_http() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let state = Arc::new(super::init(pool.clone(), &config, Default::default()).await?);
        let app = router(state, known_ident());
        let scan = sample_scan("scan-results-ranges");

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        insert_results(&pool, &scan.scan_id).await?;

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}/results", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let results: Vec<models::Result> = body_json(response).await;
        assert_eq!(
            results.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}/results?range=1", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let results: Vec<models::Result> = body_json(response).await;
        assert_eq!(results.iter().map(|r| r.id).collect::<Vec<_>>(), vec![1, 2]);

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}/results?range=1-1", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let results: Vec<models::Result> = body_json(response).await;
        assert_eq!(results.iter().map(|r| r.id).collect::<Vec<_>>(), vec![1]);

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}/results?range=-1", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let results: Vec<models::Result> = body_json(response).await;
        assert_eq!(results.iter().map(|r| r.id).collect::<Vec<_>>(), vec![0, 1]);

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/scans/{}/results?range=23", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let results: Vec<models::Result> = body_json(response).await;
        assert!(results.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn get_scan_status_via_http() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, known_ident());
        let scan = sample_scan("scan-status");

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let status = scan_status(&app, &scan.scan_id).await?;
        assert!(status.is_object());
        Ok(())
    }

    #[tokio::test]
    async fn starting_a_non_stored_scan_returns_conflict_per_openapi() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, known_ident());
        let scan = sample_scan("scan-start-twice");

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let start_body = serde_json::to_vec(&models::ScanAction {
            action: models::Action::Start,
        })?;

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(start_body.clone()))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Running,
            Duration::from_secs(2),
        )
        .await?;

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(start_body))?,
        )
        .await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
        Ok(())
    }

    #[tokio::test]
    async fn starting_a_stopped_scan_is_allowed() -> crate::Result<()> {
        let state = create_scan_state().await?;
        let app = router(state, known_ident());
        let scan = sample_scan("scan-restart-after-stop");

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let start_body = serde_json::to_vec(&models::ScanAction {
            action: models::Action::Start,
        })?;
        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(start_body.clone()))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Running,
            Duration::from_secs(2),
        )
        .await?;

        let stop_body = serde_json::to_vec(&models::ScanAction {
            action: models::Action::Stop,
        })?;
        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(stop_body))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Stopped,
            Duration::from_secs(2),
        )
        .await?;

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(start_body))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Running,
            Duration::from_secs(2),
        )
        .await?;
        Ok(())
    }
}
