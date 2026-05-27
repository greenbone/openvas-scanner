use std::sync::Arc;

use crate::framework::{
    DeleteScansIDError, GetScansError, GetScansIDError, GetScansIDResultsError,
    GetScansIDResultsIDError, GetScansIDStatusError, PostScansError, PostScansIDError,
    StreamResult,
};
use axum::Router;
use futures::TryStreamExt;
use scannerlib::{
    PromiseRef,
    models::{self, PreferenceValue, ScanPreferenceInformation},
};
use tracing::instrument;

use crate::{
    app::AppState,
    container_image_scanner::scheduling::db::{DBResults, DataBase, scan::DBScan},
    crypt::{ChaCha20Crypt, Crypt},
    database::dao::{Execute, Fetch, RetryExec, StreamFetch},
    framework,
    scan_routes::{ScanBackend, ScanRoutes},
};

pub struct ScanState<E = ChaCha20Crypt> {
    pub pool: DataBase,
    pub crypter: Arc<E>,
}

impl<E> Clone for ScanState<E> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            crypter: self.crypter.clone(),
        }
    }
}

pub struct Scans<E = ChaCha20Crypt> {
    pub pool: DataBase,
    pub crypter: Arc<E>,
}

impl<E> Clone for Scans<E> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            crypter: self.crypter.clone(),
        }
    }
}

impl<E> Scans<E>
where
    E: Send + Sync + 'static,
{
    async fn contains_scan_id(&self, client_id: &str, scan_id: &str) -> Option<String> {
        framework::map_contains_scan_id(DBScan::new(&self.pool, (client_id, scan_id)).fetch().await)
    }

    #[instrument(skip_all, fields(client_id=client_id, scan_id=scan.scan_id))]
    pub async fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Result<String, PostScansError>
    where
        E: Crypt,
    {
        let scan_id = scan.scan_id.clone();
        framework::map_post_scan_result(
            DBScan::new(
                &self.pool,
                (self.crypter.as_ref(), client_id.as_str(), &scan),
            )
            .exec()
            .await,
            scan_id,
        )
        .map(|_| scan.scan_id.clone())
    }

    pub fn router(self) -> Router
    where
        E: Crypt,
    {
        ScanRoutes::new(self, "/container-image-scanner").router()
    }
}

impl<E> ScanBackend for Scans<E>
where
    E: Crypt + Send + Sync + 'static,
{
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
            DBScan::new(&self.pool, client_id)
                .stream_fetch()
                .map_err(framework::into_get_scans_error),
        )
    }

    fn get_scans_preferences(&self) -> PromiseRef<'_, Vec<models::ScanPreferenceInformation>> {
        Box::pin(async move {
            vec![
                ScanPreferenceInformation {
                    id: "accept_invalid_certs",
                    name: "Accepts certificates without trust chain verification",
                    default: PreferenceValue::Bool(true),
                    description: "This disables the CA chain verification for TLS certificates when connecting to a registry. This is useful for self-signed certificates.",
                },
                ScanPreferenceInformation {
                    id: "registry_allow_insecure",
                    name: "Use HTTP instead of HTTPS",
                    default: PreferenceValue::Bool(false),
                    description: "This allows unencrypted communication with an registry (HTTP instead of HTTPS).",
                },
            ]
        })
    }

    fn get_scans_id(&self, id: String) -> PromiseRef<'_, Result<models::Scan, GetScansIDError>> {
        Box::pin(async move {
            DBScan::new(&self.pool, (self.crypter.as_ref(), id))
                .fetch()
                .await
                .map_err(GetScansError::from_external)
        })
    }

    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<models::Result, GetScansIDResultsError> {
        Box::pin(
            DBResults::new(&self.pool, (id, from, to))
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
                DBResults::new(&self.pool, (id, result_id)).fetch().await,
            )
        })
    }

    fn get_scans_id_status(
        &self,
        id: String,
    ) -> PromiseRef<'_, Result<models::Status, GetScansIDStatusError>> {
        Box::pin(async move {
            DBScan::new(&self.pool, id)
                .fetch()
                .await
                .map_err(GetScansIDStatusError::from_external)
        })
    }

    fn post_scans_id(
        &self,
        id: String,
        action: models::Action,
    ) -> PromiseRef<'_, Result<(), PostScansIDError>> {
        Box::pin(async move {
            DBScan::new(&self.pool, (id, action))
                .retry_exec()
                .await
                .map_err(PostScansIDError::from_external)
        })
    }

    fn delete_scans_id(&self, id: String) -> PromiseRef<'_, Result<(), DeleteScansIDError>> {
        Box::pin(async move {
            let db = DBScan::new(&self.pool, id);
            let phase: models::Phase = db
                .fetch()
                .await
                .map_err(DeleteScansIDError::from_external)?;
            if phase.is_running() {
                return Err(DeleteScansIDError::Running);
            }
            db.retry_exec()
                .await
                .map_err(DeleteScansIDError::from_external)
        })
    }
}

impl Scans<ChaCha20Crypt> {
    pub fn from_appstate(app_state: &AppState<'_>) -> Self {
        let state = app_state.cis_scan_state.clone();
        Self {
            pool: state.pool.clone(),
            crypter: state.crypter.clone(),
        }
    }
}

#[cfg(test)]
pub mod scans_utils {
    use std::sync::Arc;

    use scannerlib::models;

    use super::Scans;
    use crate::{
        container_image_scanner::{
            Config, MIGRATOR,
            config::DBLocation,
            config_to_crypt,
            image::{DockerRegistryV2, extractor::filtered_image},
            scheduling::{
                Scheduler,
                db::{DataBase, scan::DBScan},
            },
        },
        crypt::ChaCha20Crypt,
        database::dao::{Fetch, RetryExec},
    };
    use scannerlib::notus::products_loader;

    pub struct Fakes {
        pub entry: Scans<ChaCha20Crypt>,
        pub scheduler: Scheduler<DockerRegistryV2, filtered_image::Extractor, ChaCha20Crypt>,
    }

    impl Fakes {
        pub async fn init() -> Self {
            let mut config = Config::default();
            config.database = crate::container_image_scanner::config::SqliteConfiguration {
                location: DBLocation::InMemory,
                ..Default::default()
            };
            let pool = DataBase::connect(&config.database.location.sqlite_address("test"))
                .await
                .expect("inmemory database must be available");
            MIGRATOR.run(&pool).await.expect("migrations must succeed");

            let crypter = Arc::new(config_to_crypt(&config));
            let products_path =
                concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/notus/products");
            let scheduler =
                Scheduler::<DockerRegistryV2, filtered_image::Extractor, ChaCha20Crypt>::init(
                    config.into(),
                    pool.clone(),
                    crypter.clone(),
                    products_loader(products_path, false),
                )
                .await
                .unwrap();

            Self {
                entry: Scans { pool, crypter },
                scheduler,
            }
        }

        pub fn pool(&self) -> DataBase {
            self.scheduler.pool()
        }

        pub async fn internal_id(&self, client_id: &str, scan_id: &str) -> String {
            self.entry
                .contains_scan_id(client_id, scan_id)
                .await
                .unwrap()
        }

        pub async fn simulate_start_scan(
            &mut self,
            client_id: &str,
            scan: models::Scan,
        ) -> (String, models::Status) {
            let scan_id = self
                .entry
                .post_scans(client_id.to_owned(), scan)
                .await
                .unwrap();
            let id = self.internal_id(client_id, &scan_id).await;
            DBScan::new(&self.entry.pool, (id.clone(), models::Action::Start))
                .retry_exec()
                .await
                .unwrap();

            let status = DBScan::new(&self.entry.pool, id).fetch().await.unwrap();

            (scan_id, status)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::framework::{ClientHash, ClientIdentifier};
    use axum::{
        Extension, Router,
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use mockito::{Matcher, ServerGuard};
    use scannerlib::models;
    use serde::de::DeserializeOwned;
    use sqlx::query_scalar;
    use tower::ServiceExt;

    use super::Scans;
    use crate::{
        container_image_scanner::{
            Config, MIGRATOR,
            config::DBLocation,
            config_to_crypt,
            image::{
                DockerRegistryV2, DockerRegistryV2Mock, Image as CisImage, RegistrySetting,
                extractor::filtered_image, packages::AllTypes,
            },
            scheduling::{Scheduler, db::DataBase},
        },
        crypt::ChaCha20Crypt,
    };
    use scannerlib::notus::products_loader;

    struct Fakes {
        pool: DataBase,
        crypter: Arc<ChaCha20Crypt>,
        scheduler: Scheduler<DockerRegistryV2, filtered_image::Extractor, ChaCha20Crypt>,
    }

    impl Fakes {
        fn config_without_retries() -> Config {
            let mut config = Config::default();
            config.database = crate::container_image_scanner::config::SqliteConfiguration {
                location: DBLocation::InMemory,
                ..Default::default()
            };
            config.image.scanning_retries = 0;
            config.image.retry_timeout = Duration::from_millis(1);
            config
        }

        async fn init_with_config(config: Config) -> Self {
            let pool = DataBase::connect(&config.database.location.sqlite_address("test"))
                .await
                .expect("inmemory database must be available");
            MIGRATOR
                .run(&pool)
                .await
                .expect("need migrated database scheme");

            let crypter = Arc::new(config_to_crypt(&config));
            let products_path =
                concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/notus/products");
            let scheduler =
                Scheduler::<DockerRegistryV2, filtered_image::Extractor, ChaCha20Crypt>::init(
                    config.into(),
                    pool.clone(),
                    crypter.clone(),
                    products_loader(products_path, false),
                )
                .await
                .unwrap();

            Self {
                pool,
                crypter,
                scheduler,
            }
        }

        async fn init() -> Self {
            Self::init_with_config(Self::config_without_retries()).await
        }

        fn app(&self, ident: ClientIdentifier) -> Router {
            Scans {
                pool: self.pool.clone(),
                crypter: self.crypter.clone(),
            }
            .router()
            .layer(Extension(ident))
        }

        async fn run_scheduler_rounds(&self, rounds: usize) {
            for _ in 0..rounds {
                self.scheduler.on_schedule::<AllTypes>().await;
            }
        }

        fn insecure_scan(hosts: Vec<String>) -> models::Scan {
            models::Scan {
                scan_id: uuid::Uuid::new_v4().to_string(),
                target: models::Target {
                    hosts,
                    credentials: vec![],
                    ..Default::default()
                },
                scan_preferences: vec![(RegistrySetting::Insecure.preference_key(), "true").into()],
                ..Default::default()
            }
        }

        fn success_scan(registry: &str) -> models::Scan {
            let hosts = DockerRegistryV2Mock::supported_images()
                .into_iter()
                .map(|mut image| {
                    image.registry = registry.to_string();
                    image.to_string()
                })
                .collect();
            Self::insecure_scan(hosts)
        }

        async fn start_scan_and_run(
            &self,
            app: &Router,
            scan: &models::Scan,
            rounds: usize,
        ) -> crate::Result<()> {
            let response = send(
                app,
                Request::builder()
                    .method(Method::POST)
                    .uri("/container-image-scanner/scans")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(scan)?))?,
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);

            let response = send(
                app,
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/container-image-scanner/scans/{}", scan.scan_id))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&models::ScanAction {
                        action: models::Action::Start,
                    })?))?,
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            self.run_scheduler_rounds(rounds).await;
            Ok(())
        }
    }

    fn known_ident() -> ClientIdentifier {
        ClientIdentifier::Known(ClientHash::default())
    }

    fn other_ident() -> ClientIdentifier {
        ClientIdentifier::Known(ClientHash::from("other-user"))
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

    async fn status_for_scan_id(app: &Router, scan_id: &str) -> crate::Result<serde_json::Value> {
        let response = send(
            app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/container-image-scanner/scans/{scan_id}/status"))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(body_json(response).await)
    }

    async fn wait_for_scan_phase(
        app: &Router,
        scan_id: &str,
        phase: models::Phase,
        timeout: Duration,
    ) -> crate::Result<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let status = status_for_scan_id(app, scan_id).await?;
            let current = status
                .get("status")
                .and_then(|value| value.as_str())
                .ok_or_else(|| std::io::Error::other("missing status field"))?
                .parse::<models::Phase>()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if current == phase {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "scan {scan_id} did not reach phase {:?} within {:?}, last phase: {:?}",
                    phase, timeout, current
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn image_host(registry: &str, image: Option<&str>, tag: Option<&str>) -> String {
        CisImage {
            registry: registry.to_string(),
            image: image.map(str::to_string),
            tag: tag.map(str::to_string),
        }
        .to_string()
    }

    fn auth_header(server: &ServerGuard) -> String {
        format!(
            r#"Bearer realm=\"http://{}/token\""#,
            server.host_with_port()
        )
    }

    fn mock_registry_bearer_auth(
        server: &mut ServerGuard,
        token_status: usize,
    ) -> Vec<mockito::Mock> {
        vec![
            server
                .mock("GET", "/v2/")
                .with_status(401)
                .with_header("WWW-Authenticate", &auth_header(server))
                .create(),
            server
                .mock("GET", "/token")
                .match_query(Matcher::Any)
                .with_status(token_status)
                .with_header("Content-Type", "application/json")
                .with_body(r#"{"token":"waldfee"}"#)
                .create(),
        ]
    }

    #[tokio::test]
    async fn post_list_and_get_scan_via_http() -> crate::Result<()> {
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::insecure_scan(vec!["oci://localhost/test/myimage".to_string()]);

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/container-image-scanner/scans")
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
                .uri("/container-image-scanner/scans")
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
                .uri(format!("/container-image-scanner/scans/{}", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let returned_scan: models::Scan = body_json(response).await;
        assert_eq!(returned_scan.scan_id, scan.scan_id);
        assert_eq!(returned_scan.target.hosts, scan.target.hosts);
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_scan_id_is_rejected_via_http() -> crate::Result<()> {
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::insecure_scan(vec!["oci://localhost/test/myimage".to_string()]);
        let body = serde_json::to_vec(&scan)?;

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/container-image-scanner/scans")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/container-image-scanner/scans")
                .header("content-type", "application/json")
                .body(Body::from(body))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        Ok(())
    }

    #[tokio::test]
    async fn scan_preferences_are_available_via_http() -> crate::Result<()> {
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri("/container-image-scanner/scans/preferences")
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
        let fakes = Fakes::init().await;
        let owner_app = fakes.app(known_ident());
        let other_app = fakes.app(other_ident());
        let scan = Fakes::insecure_scan(vec!["oci://localhost/test/myimage".to_string()]);

        let response = send(
            &owner_app,
            Request::builder()
                .method(Method::POST)
                .uri("/container-image-scanner/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            &other_app,
            Request::builder()
                .method(Method::GET)
                .uri(format!("/container-image-scanner/scans/{}", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn start_scan_transitions_to_requested_via_http() -> crate::Result<()> {
        let registry = DockerRegistryV2Mock::serve_default().await;
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::success_scan(&registry.address());

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/container-image-scanner/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/container-image-scanner/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&models::ScanAction {
                    action: models::Action::Start,
                })?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let status = status_for_scan_id(&app, &scan.scan_id).await?;
        assert_eq!(
            status.get("status").and_then(|value| value.as_str()),
            Some("requested")
        );
        Ok(())
    }

    #[tokio::test]
    async fn stop_scan_is_visible_via_http() -> crate::Result<()> {
        let registry = DockerRegistryV2Mock::serve_default().await;
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::success_scan(&registry.address());

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/container-image-scanner/scans")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&scan)?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/container-image-scanner/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&models::ScanAction {
                    action: models::Action::Start,
                })?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri(format!("/container-image-scanner/scans/{}", scan.scan_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&models::ScanAction {
                    action: models::Action::Stop,
                })?))?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let status = wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Stopped,
            Duration::from_secs(2),
        )
        .await?;
        assert_eq!(
            status.get("status").and_then(|value| value.as_str()),
            Some("stopped")
        );
        Ok(())
    }

    #[tokio::test]
    async fn start_scan_succeeded_via_http_after_scheduler_rounds() -> crate::Result<()> {
        let registry = DockerRegistryV2Mock::serve_default().await;
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::success_scan(&registry.address());

        fakes
            .start_scan_and_run(&app, &scan, scan.target.hosts.len())
            .await?;

        let status = wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Succeeded,
            Duration::from_secs(2),
        )
        .await?;
        assert_eq!(
            status.get("status").and_then(|value| value.as_str()),
            Some("succeeded")
        );

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/container-image-scanner/scans/{}/results",
                    scan.scan_id
                ))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let results: Vec<models::Result> = body_json(response).await;
        assert!(!results.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn delete_scan_removes_results_via_http() -> crate::Result<()> {
        let registry = DockerRegistryV2Mock::serve_default().await;
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::success_scan(&registry.address());

        fakes
            .start_scan_and_run(&app, &scan, scan.target.hosts.len())
            .await?;
        wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Succeeded,
            Duration::from_secs(2),
        )
        .await?;

        let response = send(
            &app,
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/container-image-scanner/scans/{}", scan.scan_id))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/container-image-scanner/scans/{}/results",
                    scan.scan_id
                ))
                .body(Body::empty())?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let count: i64 = query_scalar("SELECT count(id) FROM client_scan_map WHERE scan_id = ?")
            .bind(&scan.scan_id)
            .fetch_one(&fakes.pool)
            .await?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn start_scan_failed_when_tag_resolution_returns_no_images() -> crate::Result<()> {
        let mut server = mockito::Server::new_async().await;
        let _auth = mock_registry_bearer_auth(&mut server, 200);
        let _catalog = server
            .mock("GET", "/v2/_catalog")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"repositories":["nichtsfrei/victim"]}"#)
            .create();
        let _tags = server
            .mock("GET", "/v2/nichtsfrei/victim/tags/list")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"name":"nichtsfrei/victim","tags":[]}"#)
            .create();

        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::insecure_scan(vec![image_host(
            &server.host_with_port(),
            Some("nichtsfrei/victim"),
            None,
        )]);

        fakes.start_scan_and_run(&app, &scan, 1).await?;

        let status = wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Failed,
            Duration::from_secs(2),
        )
        .await?;
        assert_eq!(
            status.get("status").and_then(|value| value.as_str()),
            Some("failed")
        );
        Ok(())
    }

    #[tokio::test]
    async fn start_scan_failed_when_registry_authentication_returns_503() -> crate::Result<()> {
        let mut server = mockito::Server::new_async().await;
        let _auth = mock_registry_bearer_auth(&mut server, 503);

        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());
        let scan = Fakes::insecure_scan(vec![image_host(
            &server.host_with_port(),
            Some("nichtsfrei/victim"),
            Some("latest"),
        )]);

        fakes.start_scan_and_run(&app, &scan, 1).await?;

        let status = wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Failed,
            Duration::from_secs(2),
        )
        .await?;
        assert_eq!(
            status.get("status").and_then(|value| value.as_str()),
            Some("failed")
        );
        Ok(())
    }

    #[tokio::test]
    async fn start_scan_failed_when_blob_download_returns_503() -> crate::Result<()> {
        let mut image = DockerRegistryV2Mock::supported_images()
            .into_iter()
            .next()
            .unwrap();
        image.registry = Default::default();
        let registry =
            DockerRegistryV2Mock::serve_images(&[image.clone()], &[0, 0, 200, 200, 200, 200, 503])
                .await;

        image.registry = registry.address();
        let scan = Fakes::insecure_scan(vec![image.to_string()]);
        let fakes = Fakes::init().await;
        let app = fakes.app(known_ident());

        fakes.start_scan_and_run(&app, &scan, 1).await?;

        let status = wait_for_scan_phase(
            &app,
            &scan.scan_id,
            models::Phase::Failed,
            Duration::from_secs(2),
        )
        .await?;
        assert_eq!(
            status.get("status").and_then(|value| value.as_str()),
            Some("failed")
        );
        Ok(())
    }
}
