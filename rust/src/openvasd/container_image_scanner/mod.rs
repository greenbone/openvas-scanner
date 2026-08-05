pub mod config;
mod detection;
mod image;
mod messages;
mod notus;
mod scheduling;
mod timings;

pub use config::Config;
#[cfg(test)]
pub(crate) use image::DockerRegistryV2Mock;
pub(crate) use scannerlib::{ExternalError, PromiseRef, Streamer};
pub use scheduling::db::scan::DBScan;

use std::sync::Arc;

use crate::api::states::ScannerBridge;
use scannerlib::notus::Notus;
use scheduling::Scheduler;
use sqlx::migrate::Migrator;

static MIGRATOR: Migrator = sqlx::migrate!("./src/openvasd/container_image_scanner/migrations");

pub async fn init(
    products: Arc<tokio::sync::RwLock<Notus>>,
    config: Config,
) -> anyhow::Result<ScannerBridge> {
    let pool = config
        .database
        .create_pool("container-image-scanner")
        .await?;
    MIGRATOR.run(&pool).await?;

    let scheduler = Scheduler::init(config.into(), pool.clone(), products);
    tokio::spawn(scheduler.run());

    Ok(ScannerBridge::new(pool, None, None))
}

#[cfg(test)]
pub mod scans_utils {

    use std::{sync::Arc, time::Duration};

    use tokio::sync::Mutex;

    use crate::{
        api::states::ScannerBridge,
        container_image_scanner::{
            Config, MIGRATOR,
            config::DBLocation,
            image::{DockerRegistryV2Mock, RegistryPreference},
            scheduling::{Scheduler, db::DataBase},
        },
    };
    use scannerlib::models;
    use scannerlib::notus::products_loader;

    async fn in_memory_scheduler_and_scan(
        config: crate::container_image_scanner::Config,
    ) -> (Scheduler, ScannerBridge) {
        let pool = DataBase::connect(&DBLocation::InMemory.sqlite_address("test"))
            .await
            .expect("inmemory database must be available");

        MIGRATOR
            .run(&pool)
            .await
            .expect("need migrated database scheme");
        let products_path: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/notus/products");

        let scheduler = Scheduler::init(
            config.into(),
            pool.clone(),
            products_loader(products_path, false),
        );
        let scans = ScannerBridge {
            pool: pool.clone(),
            crypter: None,
            scheduler: None,
        };
        (scheduler, scans)
    }

    pub struct Fakes {
        registry: DockerRegistryV2Mock,
        pub entry: ScannerBridge,
        pub scheduler: Scheduler,
    }

    impl Fakes {
        pub async fn internal_id(&self, client_id: &str, scan_id: &str) -> String {
            self.entry
                .get_scan_id(client_id, scan_id)
                .await
                .expect("scan must exist")
                .to_string()
        }

        pub async fn simulate_stop_scan(
            &mut self,
            client_id: &str,
            scan_id: &str,
        ) -> models::Status {
            self.entry
                .schedule_scan(client_id, scan_id, models::Action::Stop)
                .await
                .expect("scan must be scheduled to stop");

            self.entry
                .get_scan_status(client_id, scan_id)
                .await
                .expect("scan must have a status")
        }

        pub async fn simulate_start_scan(
            &mut self,
            client_id: &str,
            scan: models::Scan,
        ) -> (String, models::Status) {
            let scan_id = scan.scan_id.clone();
            self.entry
                .post_scan(client_id, &scan)
                .await
                .expect("scan must be added");

            self.entry
                .schedule_scan(client_id, &scan_id, models::Action::Start)
                .await
                .expect("scan must be scheduled");
            (
                scan_id.clone(),
                self.entry
                    .get_scan_status(client_id, &scan_id)
                    .await
                    .expect("scan must have a status"),
            )
        }

        pub async fn init() -> Self {
            Self::init_with_config(Config::default()).await
        }

        pub async fn init_with_config(config: Config) -> Self {
            let registry = DockerRegistryV2Mock::serve_default().await;
            let (scheduler, entry) = in_memory_scheduler_and_scan(config).await;

            Self {
                registry,
                entry,
                scheduler,
            }
        }

        async fn create_start_scan(&mut self, client_id: &str, scan: models::Scan) -> String {
            let (scan_id, _) = self.simulate_start_scan(client_id, scan).await;
            scan_id
        }

        pub async fn run_scheduler_rounds(&self, rounds: usize) {
            let conn = Arc::new(Mutex::new(self.scheduler.pool()));
            for _ in 0..rounds {
                Scheduler::start_scans(
                    self.scheduler.config(),
                    conn.clone(),
                    self.scheduler.products(),
                )
                .await;
            }
        }

        pub async fn status_for_scan_id(&self, client_id: &str, scan_id: &str) -> models::Status {
            self.entry
                .get_scan_status(client_id, scan_id)
                .await
                .expect("scan must have a status")
        }

        pub async fn start_scan_and_run(
            &mut self,
            client_id: &str,
            scan: models::Scan,
            rounds: usize,
        ) -> (String, models::Status) {
            let (scan_id, _) = self.simulate_start_scan(client_id, scan).await;
            self.run_scheduler_rounds(rounds).await;
            let status = self.status_for_scan_id(client_id, &scan_id).await;
            (scan_id, status)
        }

        pub async fn create_start_results(
            &mut self,
            client_id: &str,
            scan: models::Scan,
        ) -> (String, models::Status) {
            let scans = scan.target.hosts.len();
            let scan_id = self.create_start_scan(client_id, scan).await;
            self.run_scheduler_rounds(scans).await;
            let id = self
                .entry
                .get_scan_id(client_id, &scan_id)
                .await
                .expect("scan must exist")
                .to_string();
            let result = self
                .entry
                .get_scan_status(client_id, &scan_id)
                .await
                .expect("scan must have a status");

            (id, result)
        }

        pub fn insecure_scan<I, H>(&self, scan_id: impl Into<String>, hosts: I) -> models::Scan
        where
            I: IntoIterator<Item = H>,
            H: Into<String>,
        {
            models::Scan {
                scan_id: scan_id.into(),
                target: models::Target {
                    hosts: hosts.into_iter().map(Into::into).collect(),
                    ..Default::default()
                },
                scan_preferences: vec![(RegistryPreference::Insecure.key(), "true").into()],
                ..Default::default()
            }
        }

        pub fn success_scan(&self) -> models::Scan {
            let credentials = vec![];
            let hosts = DockerRegistryV2Mock::supported_images()
                .clone()
                .into_iter()
                .map(|mut x| {
                    x.registry = self.registry.address().into();
                    x.to_string()
                })
                .collect();

            let target = models::Target {
                hosts,
                credentials,
                ..Default::default()
            };
            let scan_preferences = vec![(RegistryPreference::Insecure.key(), "true").into()];

            models::Scan {
                scan_id: uuid::Uuid::new_v4().to_string(),
                target,
                scan_preferences,
                ..Default::default()
            }
        }
        pub fn pool(&self) -> DataBase {
            self.scheduler.pool()
        }

        pub fn config_without_retries() -> Config {
            let mut config = Config::default();
            config.image.scanning_retries = 0;
            config.image.retry_timeout = Duration::from_millis(1);
            config
        }

        #[allow(dead_code)]
        /// This is just a toggle to temporally use logging
        fn init_logging() {
            let filter = tracing_subscriber::filter::Targets::new()
                .with_default(tracing::Level::WARN)
                .with_target("greenbone_scanner_framework", tracing::Level::INFO)
                .with_target("container_scanning", tracing::Level::TRACE);
            let layer = tracing_subscriber::fmt::layer()
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL);
            tracing_subscriber::util::SubscriberInitExt::init(
                tracing_subscriber::layer::SubscriberExt::with(
                    tracing_subscriber::layer::SubscriberExt::with(
                        tracing_subscriber::registry(),
                        layer,
                    ),
                    filter,
                ),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use futures::StreamExt;
    use scannerlib::models::{self, Phase};
    use sqlx::query_scalar;

    use crate::{
        api::error::ApiError,
        container_image_scanner::{image::DockerRegistryV2Mock, scans_utils::Fakes},
    };

    const CLIENT_ID: &str = "client1";

    fn auth_header(registry: &mockito::ServerGuard) -> String {
        format!(
            r#"Bearer realm="http://{}/token""#,
            registry.host_with_port()
        )
    }

    fn mock_registry_bearer_auth(
        registry: &mut mockito::ServerGuard,
        scope: &str,
        token_status: usize,
    ) -> (mockito::Mock, mockito::Mock) {
        let v2 = registry
            .mock("GET", "/v2/")
            .with_status(401)
            .with_header("WWW-Authenticate", &auth_header(registry))
            .expect_at_least(1)
            .create();
        let token = registry
            .mock("GET", "/token")
            .match_query(mockito::Matcher::UrlEncoded(
                "scope".into(),
                scope.to_owned(),
            ))
            .with_status(token_status)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"token": "waldfee"}"#)
            .create();
        (v2, token)
    }

    #[tokio::test]
    async fn post_scan_double_id() {
        let entry = Fakes::init().await.entry;
        let scan = models::Scan {
            scan_id: "test".to_owned(),
            ..Default::default()
        };
        entry
            .post_scan(CLIENT_ID, &scan)
            .await
            .expect("scans must be added");
        let result = entry.post_scan(CLIENT_ID, &scan).await;
        assert!(
            matches!(result, Err(crate::database::dao::DAOError::DBViolation(_))),
            "expected duplicate id result"
        );
    }

    #[tokio::test]
    async fn post_scan() {
        let entry = Fakes::init().await.entry;
        let hosts = vec!["oci://localhost/test/myimage".to_owned()];
        let credentials = vec![models::Credential {
            credential_type: models::CredentialType::UP {
                username: "me".to_owned(),
                password: "password".to_owned(),
                privilege: None,
            },
            ..Default::default()
        }];

        let target = models::Target {
            hosts,
            credentials,
            ..Default::default()
        };
        let scan = models::Scan {
            scan_id: "test".to_owned(),
            target,
            ..Default::default()
        };
        entry
            .post_scan(CLIENT_ID, &scan)
            .await
            .expect("scan must be added");
        let result = entry
            .get_scan(CLIENT_ID, &scan.scan_id)
            .await
            .expect("scan must exist");
        assert_eq!(scan.scan_id, result.scan_id);
        assert_eq!(scan.target.hosts, result.target.hosts);
    }

    #[tokio::test]
    async fn start_scan() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();

        let (_, status) = fakes.simulate_start_scan(CLIENT_ID, scan).await;
        assert_eq!(status.status, Phase::Requested);
        Ok(())
    }

    #[tokio::test]
    async fn stop_scan() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();

        let (id, status) = fakes.simulate_start_scan(CLIENT_ID, scan).await;

        assert_eq!(status.status, Phase::Requested);

        let status = fakes.simulate_stop_scan(CLIENT_ID, &id).await;

        assert_eq!(status.status, Phase::Stopped);
        Ok(())
    }

    #[tokio::test]
    async fn delete_scan_running() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();

        let (scan_id, _) = fakes.simulate_start_scan(CLIENT_ID, scan).await;

        let result = fakes.entry.delete_scan(CLIENT_ID, &scan_id).await;
        assert!(matches!(result, Err(ApiError::ScanRunning)));
        Ok(())
    }

    #[tokio::test]
    async fn delete_scan() {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let scan_id = scan.scan_id.clone();
        let _ = fakes.create_start_results(CLIENT_ID, scan).await;
        let result = fakes
            .entry
            .get_scan_results(CLIENT_ID, &scan_id, None, None);
        let result: Vec<_> = result
            .await
            .expect("scan must have results")
            .collect()
            .await;

        let result: Vec<_> = result
            .into_iter()
            .filter_map(|x| x.ok())
            .map(|x| x.id)
            .collect();
        assert!(!result.is_empty(), "expected results");

        fakes
            .entry
            .delete_scan(CLIENT_ID, &scan_id)
            .await
            .expect("scan must be deleted");
        let result = fakes
            .entry
            .get_scan_results(CLIENT_ID, &scan_id, None, None)
            .await;
        assert!(matches!(
            result,
            Err(ApiError::Database(crate::database::dao::DAOError::NotFound))
        ));

        let count: i64 = query_scalar("SELECT count(id) FROM client_scan_map WHERE id = ?")
            .bind(scan_id)
            .fetch_one(&fakes.entry.pool)
            .await
            .expect("scan must be in the DB");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn start_scan_succeeded() {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let (_, status) = fakes.create_start_results(CLIENT_ID, scan).await;

        let result = status.status;
        assert_eq!(result, Phase::Succeeded);
    }

    #[tokio::test]
    // Regression for when no images got found and the scan sticked to requested.
    async fn start_scan_failed_when_tag_resolution_returns_no_images() {
        let mut fakes = Fakes::init().await;
        let mut registry = mockito::Server::new_async().await;
        let _auth =
            mock_registry_bearer_auth(&mut registry, "repository:nichtsfrei/victim:pull", 200);
        let _tags = registry
            .mock("GET", "/v2/nichtsfrei/victim/tags/list")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"name": "nichtsfrei/victim", "tags": []}"#)
            .expect(1)
            .create();

        let scan = fakes.insecure_scan(
            "empty-tag-resolution",
            [format!(
                "oci://{}/nichtsfrei/victim",
                registry.host_with_port()
            )],
        );

        let (_, status) = fakes.start_scan_and_run(CLIENT_ID, scan, 1).await;

        assert_eq!(status.status, Phase::Failed);
        let host_info = status.host_info.expect("status should include host info");
        assert_eq!(host_info.all, 0);
        assert_eq!(host_info.dead, 0);
        assert_eq!(host_info.queued, 0);
    }

    #[tokio::test]
    async fn start_scan_failed_when_registry_authentication_returns_503() {
        let mut fakes = Fakes::init_with_config(Fakes::config_without_retries()).await;
        let mut registry = mockito::Server::new_async().await;
        let _auth =
            mock_registry_bearer_auth(&mut registry, "repository:nichtsfrei/victim:pull", 503);

        let scan = fakes.insecure_scan(
            "auth-503-during-scan",
            [format!(
                "oci://{}/nichtsfrei/victim:latest",
                registry.host_with_port()
            )],
        );

        let (_, status) = fakes.start_scan_and_run(CLIENT_ID, scan, 1).await;

        assert_eq!(status.status, Phase::Failed);
    }

    #[tokio::test]
    async fn start_scan_failed_when_blob_download_returns_503() {
        let mut fakes = Fakes::init_with_config(Fakes::config_without_retries()).await;
        let mut image = DockerRegistryV2Mock::supported_images()
            .into_iter()
            .next()
            .expect("expected at least one supported image");
        let registry = DockerRegistryV2Mock::serve_images(
            &[image.clone()],
            &[200, 200, 200, 200, 200, 200, 503],
        )
        .await;
        image.registry = registry.address().into();

        let scan = fakes.insecure_scan("blob-503-during-scan", [image.to_string()]);

        let (_, status) = fakes.start_scan_and_run(CLIENT_ID, scan, 1).await;

        assert_eq!(status.status, Phase::Failed);
    }

    #[tokio::test]
    async fn get_scans() {
        let client2_id = "client2";
        let entry = Fakes::init().await.entry;
        for i in 0..10 {
            let scan = models::Scan {
                scan_id: i.to_string(),
                ..Default::default()
            };
            let client_id = if i % 2 == 0 { CLIENT_ID } else { client2_id };
            entry
                .post_scan(client_id, &scan)
                .await
                .expect("post scans should succeed");
        }
        let result = entry.get_scans(CLIENT_ID.to_string()).await;
        assert_eq!(result.filter_map(async move |x| x.ok()).count().await, 5);

        let result = entry.get_scans(client2_id.to_string()).await;
        assert_eq!(result.filter_map(async move |x| x.ok()).count().await, 5);

        let result = entry.get_scans("client3_id".to_string()).await;
        assert_eq!(result.filter_map(async move |x| x.ok()).count().await, 0);
    }

    mod results {
        use super::*;

        #[tokio::test]
        async fn all() {
            let mut fakes = Fakes::init().await;
            let scan = fakes.success_scan();
            let _ = fakes.create_start_results(CLIENT_ID, scan.clone()).await;
            let result = fakes
                .entry
                .get_scan_results(CLIENT_ID, &scan.scan_id, None, None)
                .await
                .expect("scab must have results");
            let result: Vec<_> = result.collect().await;

            let result: Vec<_> = result.into_iter().filter_map(|x| x.ok()).collect();

            let internal: Vec<_> = result
                .iter()
                .filter(|x| {
                    x.oid.as_ref().map_or("", |x| x as &str) == "openvasd/container-image-scanner"
                })
                .collect();
            // internal log messages per found host
            assert_eq!(
                internal.len(),
                // best_os, best_os_cpe, hostname, architecture,
                // packages, download, extract, scan, combined
                // timings, host, start, host end per image
                fakes.success_scan().target.hosts.len() * 11,
                "Expected internal log messages"
            );
            assert_eq!(
                result
                    .iter()
                    .filter_map(|x| x.oid.as_ref())
                    .filter(|x| x as &str != "openvasd/container-image-scanner")
                    .count(),
                275 * fakes.success_scan().target.hosts.len(),
                "Expected found vulnerabilities"
            );
        }

        #[tokio::test]
        async fn subset() {
            let mut fakes = Fakes::init().await;
            let scan = fakes.success_scan();
            let _ = fakes.create_start_results(CLIENT_ID, scan.clone()).await;
            let result = fakes
                .entry
                .get_scan_results(CLIENT_ID, &scan.scan_id, None, None)
                .await
                .expect("scan must have results");

            let all: Vec<_> = result.collect().await;
            let all: Vec<_> = all.into_iter().filter_map(|x| x.ok()).collect();
            let all = all.len();

            let check_subset = async |range: (Option<usize>, Option<usize>)| {
                let (start, end) = range;
                let results = fakes
                    .entry
                    .get_scan_results(CLIENT_ID, &scan.scan_id, start, end)
                    .await
                    .expect("scan must have results");
                let results: Vec<_> = results.collect().await;
                let results: Vec<_> = results.into_iter().filter_map(|x| x.ok()).collect();
                let or_all = |x| {
                    if x > all { None } else { Some(x) }
                };
                let normalized_range = match range {
                    (None, Some(x)) => (None, or_all(x)),
                    (Some(x), None) => (or_all(x), None),
                    (Some(x), Some(y)) => {
                        // if start is higher then end we manipulate so that zero is the output
                        if x > y {
                            (Some(all), None)
                        } else {
                            (or_all(x), or_all(y))
                        }
                    }
                    a => a,
                };
                let expted_len = match normalized_range {
                    // we are inclusive
                    (Some(a), Some(b)) => b - a + 1,
                    (None, Some(b)) => b + 1,
                    (Some(a), None) => all - a,
                    (None, None) => all,
                };
                let offset = start.unwrap_or(0);
                assert_eq!(results.len(), expted_len);
                for (i, x) in results.iter().enumerate() {
                    assert_eq!(i + offset, x.id, "expected matching result id")
                }
            };
            check_subset((Some(0), Some(5))).await;
            check_subset((Some(5), None)).await;
            check_subset((Some(5), Some(23))).await;
            check_subset((None, Some(69))).await;
            check_subset((Some(42), Some(4242))).await;
            check_subset((Some(4242), Some(10))).await;
        }

        #[tokio::test]
        async fn single_result() {
            let mut fakes = Fakes::init().await;
            let scan = fakes.success_scan();
            let _ = fakes.create_start_results(CLIENT_ID, scan.clone()).await;
            let result = fakes
                .entry
                .get_scan_result(CLIENT_ID, &scan.scan_id, 42)
                .await;
            let result = result.map(|x| x.id).expect("scan must have results");
            assert_eq!(result, 42)
        }
        #[tokio::test]
        async fn invalid_result_id() {
            let mut fakes = Fakes::init().await;
            let scan = fakes.success_scan();
            let _ = fakes.create_start_results(CLIENT_ID, scan.clone()).await;
            let result = fakes
                .entry
                .get_scan_result(CLIENT_ID, &scan.scan_id, 4242)
                .await;
            let result = result.map(|x| x.id);
            assert!(matches!(
                result,
                Err(ApiError::Database(crate::database::dao::DAOError::NotFound))
            ))
        }
    }
}
