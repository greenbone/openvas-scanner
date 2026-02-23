use std::{pin::Pin, str::FromStr};

use futures::{StreamExt, TryStreamExt};
use greenbone_scanner_framework::{
    MapScanID, StreamResult,
    entry::Prefixed,
    models::{HostInfo, PreferenceValue, ScanPreferenceInformation},
    prelude::*,
};
use sqlx::{Row, SqlitePool, query, sqlite::SqliteRow};
use tokio::sync::mpsc::Sender;
use tracing::instrument;

use crate::{
    container_image_scanner::scheduling::{self, db::scan::SqliteScan},
    database::dao::{DAOError, Fetch, Insert, StreamFetch},
};

pub struct Scans {
    pub pool: SqlitePool,
    pub scheduling: Sender<scheduling::Message>,
}

impl Prefixed for Scans {
    fn prefix(&self) -> &'static str {
        "container-image-scanner"
    }
}

impl PostScans for Scans {
    #[instrument(skip_all, fields(client_id=client_id, scan_id=scan.scan_id))]
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send + '_>> {
        Box::pin(async move {
            // maybe get rid of clone
            let scan_id = scan.scan_id.clone();
            match SqliteScan::new(client_id.as_str(), &scan, &self.pool)
                .insert()
                .await
            {
                Ok(_) => Ok(scan_id),
                Err(DAOError::UniqueConstraintViolation) => {
                    Err(PostScansError::DuplicateId(scan_id))
                }
                Err(error) => Err(PostScansError::External(Box::new(error))),
            }
        })
    }
}

impl MapScanID for Scans {
    fn contains_scan_id<'a>(
        &'a self,
        client_id: &'a str,
        scan_id: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Option<greenbone_scanner_framework::InternalIdentifier>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match SqliteScan::new(client_id, scan_id, &self.pool)
                .fetch()
                .await
            {
                Ok(x) => x,
                Err(error) => {
                    tracing::warn!(%error, "Unable to fetch id from client_scan_map. Returning no id found.");
                    None
                }
            }
        })
    }
}

impl GetScans for Scans {
    fn get_scans(&self, client_id: String) -> StreamResult<String, GetScansError> {
        let result = SqliteScan::new(client_id, (), &self.pool)
            .stream_fetch()
            .map_err(GetScansError::from_external);

        Box::pin(result)
    }
}

impl GetScansPreferences for Scans {
    fn get_scans_preferences(
        &self,
    ) -> Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>> {
        Box::pin(async move {
            vec![
                ScanPreferenceInformation {
                    id: "accept_invalid_certs",
                    name: "Accepts certificates without trust chain verification",
                    default: PreferenceValue::Bool(true),
                    description: "This disables the CA chain verification for TLS certificates when connecting to a registry. \
                    This is useful for self-signed certificates.",
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
}

impl GetScansId for Scans {
    fn get_scans_id<'a>(
        &'a self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send + 'a>> {
        Box::pin(async move {
            SqliteScan::new((), id, &self.pool)
                .fetch()
                .await
                .map_err(GetScansError::from_external)
        })
    }
}

impl GetScansIdResults for Scans {
    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<models::Result, GetScansIDResultsError> {
        let result = SqliteScan::new((), (id, from, to), &self.pool)
            .stream_fetch()
            .map_err(GetScansError::from_external);

        Box::pin(result)
    }
}

impl GetScansIdResultsId for Scans {
    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> Pin<Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send + '_>>
    {
        Box::pin(async move {
            SqliteScan::new((), (id, result_id), &self.pool)
                .fetch()
                .await
                .map_err(|e| match e {
                    DAOError::NotFound => GetScansIDResultsIDError::InvalidID,
                    e => e.into(),
                })
        })
    }
}

impl GetScansIdStatus for Scans {
    fn get_scans_id_status(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>>
    {
        Box::pin(async move {
            SqliteScan::new((), id, &self.pool)
                .fetch()
                .await
                .map_err(GetScansIDStatusError::from_external)
        })
    }
}

impl PostScansId for Scans {
    fn post_scans_id(
        &self,
        id: String,
        action: models::Action,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostScansIDError>> + Send + '_>> {
        let sender = self.scheduling.clone();
        Box::pin(async move {
            sender
                .send(scheduling::Message::new(id, action))
                .await
                .map_err(PostScansIDError::from_external)
        })
    }
}

impl Scans {
    async fn get_phase(&self, id: &str) -> Result<models::Phase, sqlx::Error> {
        const STATUS_SQL: &str = "SELECT status FROM scans WHERE id = ?";
        query(STATUS_SQL)
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map(|row| {
                models::Phase::from_str(&row.get::<String, _>("status"))
                    .expect("expact status to be a valid phase")
            })
    }
}

impl DeleteScansId for Scans {
    fn delete_scans_id(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send + '_>> {
        const DELETE_SQL: &str = "DELETE FROM client_scan_map WHERE id = ?";
        Box::pin(async move {
            let phase = self
                .get_phase(&id)
                .await
                .map_err(DeleteScansIDError::from_external)?;
            if phase.is_running() {
                return Err(DeleteScansIDError::Running);
            }
            query(DELETE_SQL)
                .bind(&id)
                .execute(&self.pool)
                .await
                .map(|_| ())
                .map_err(DeleteScansIDError::from_external)
        })
    }
}

#[cfg(test)]
mod scans_utils {

    use std::sync::Arc;

    use greenbone_scanner_framework::prelude::*;
    use sqlx::SqlitePool;
    use tokio::sync::Mutex;

    use super::Scans;
    use crate::{
        container_image_scanner::{
            Config, MIGRATOR,
            config::DBLocation,
            image::{
                DockerRegistryV2, DockerRegistryV2Mock, RegistrySetting, extractor::filtered_image,
                packages::AllTypes,
            },
            scheduling::{Scheduler, db},
        },
        database::sqlite::SqliteConnectionContainer,
    };
    use scannerlib::notus::path_to_products;

    pub fn client_id() -> String {
        ClientHash::default().to_string()
    }

    pub fn second_client_id() -> String {
        ClientHash::from("second").to_string()
    }

    async fn in_memory_scheduler_and_scan<R, E>(
        config: crate::container_image_scanner::Config,
    ) -> (Scheduler<R, E>, Scans) {
        let pool = SqlitePool::connect(&DBLocation::InMemory.sqlite_address("test"))
            .await
            .expect("inmemory database must be available");

        MIGRATOR
            .run(&pool)
            .await
            .expect("need migrated database scheme");
        let products_path: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/notus/products");

        let (sender, scheduler) = Scheduler::<R, E>::init(
            config.into(),
            pool.clone(),
            path_to_products(products_path, false),
        );
        let scans = super::Scans {
            pool: pool.clone(),
            scheduling: sender,
        };
        (scheduler, scans)
    }

    pub struct Fakes {
        registry: DockerRegistryV2Mock,
        pub entry: super::Scans,
        pub scheduler: Scheduler<DockerRegistryV2, filtered_image::Extractor>,
    }

    impl Fakes {
        async fn recv(&mut self) {
            let msg = self.scheduler.receiver().recv().await;
            if let Some(msg) = msg {
                db::on_message(&self.scheduler.pool(), &msg).await.unwrap();
            }
        }

        pub async fn internal_id(&self, client_id: &str, scan_id: &str) -> String {
            self.entry
                .contains_scan_id(client_id, scan_id)
                .await
                .unwrap()
        }

        pub async fn simulate_stop_scan(
            &mut self,
            client_id: &str,
            scan_id: &str,
        ) -> models::Status {
            let id = self.internal_id(client_id, scan_id).await;

            self.entry
                .post_scans_id(id.clone(), models::Action::Stop)
                .await
                .unwrap();

            self.recv().await;

            self.entry.get_scans_id_status(id).await.unwrap()
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

            self.entry
                .post_scans_id(id.clone(), models::Action::Start)
                .await
                .unwrap();

            self.recv().await;

            (scan_id, self.entry.get_scans_id_status(id).await.unwrap())
        }

        pub async fn init() -> Self {
            let registry = DockerRegistryV2Mock::serve_default().await;

            let config = Config::default();
            let (scheduler, entry) = in_memory_scheduler_and_scan(config).await;

            Self {
                registry,
                entry,
                scheduler,
            }
        }

        async fn create_start_scan<ClientID>(
            &mut self,
            client_id: &ClientID,
            scan: models::Scan,
        ) -> String
        where
            ClientID: Fn() -> String,
        {
            let (scan_id, _) = self.simulate_start_scan(&client_id(), scan).await;
            scan_id
        }

        pub async fn create_start_results<ClientID>(
            &mut self,
            client_id: &ClientID,
            scan: models::Scan,
        ) -> (String, models::Status)
        where
            ClientID: Fn() -> String,
        {
            let scans = scan.target.hosts.len();
            let scan_id = self.create_start_scan(&client_id, scan).await;
            let pool = self.scheduler.pool();
            let conn = Arc::new(Mutex::new(
                SqliteConnectionContainer::init(pool).await.unwrap(),
            ));
            for _ in 0..scans {
                Scheduler::<DockerRegistryV2, filtered_image::Extractor>::start_scans::<AllTypes>(
                    self.scheduler.config(),
                    conn.clone(),
                    self.scheduler.products(),
                )
                .await;
            }
            let id = self
                .entry
                .contains_scan_id(&client_id(), &scan_id)
                .await
                .unwrap();
            let result = self
                .entry
                .get_scans_id_status(id.clone())
                .await
                .expect("get_scans_id_status must function");

            (id, result)
        }

        pub fn success_scan(&self) -> models::Scan {
            let credentials = vec![];
            let hosts = DockerRegistryV2Mock::supported_images()
                .clone()
                .into_iter()
                .map(|mut x| {
                    x.registry = self.registry.address();
                    x.to_string()
                })
                .collect();

            let target = models::Target {
                hosts,
                credentials,
                ..Default::default()
            };
            let scan_preferences =
                vec![(RegistrySetting::Insecure.preference_key(), "true").into()];

            models::Scan {
                scan_id: uuid::Uuid::new_v4().to_string(),
                target,
                scan_preferences,
                ..Default::default()
            }
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
    use greenbone_scanner_framework::prelude::*;
    use models::Phase;
    use sqlx::query_scalar;

    use super::scans_utils::second_client_id;
    use crate::container_image_scanner::endpoints::scans::scans_utils::{Fakes, client_id};

    #[tokio::test]
    async fn post_scan_double_id() {
        let entry = Fakes::init().await.entry;
        let scan = models::Scan {
            scan_id: "test".to_owned(),
            ..Default::default()
        };
        let result = entry
            .post_scans(client_id(), scan.clone())
            .await
            .expect("post scans should succeed");
        assert_eq!(result, "test".to_owned());
        let result = entry.post_scans(client_id(), scan.clone()).await;
        assert!(
            matches!(result, Err(PostScansError::DuplicateId(_))),
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
        let result = entry
            .post_scans(client_id(), scan.clone())
            .await
            .expect("post scans should succeed");
        assert_eq!(result, "test".to_owned());
        let id = entry
            .contains_scan_id(&client_id(), &scan.scan_id)
            .await
            .unwrap();
        let result = entry.get_scans_id(id).await.unwrap();
        assert_eq!(scan.scan_id, result.scan_id);
        assert_eq!(scan.target.hosts, result.target.hosts);
    }

    #[tokio::test]
    async fn start_scan() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();

        let (_, status) = fakes.simulate_start_scan(&client_id(), scan).await;
        assert_eq!(status.status, Phase::Requested);
        Ok(())
    }

    #[tokio::test]
    async fn stop_scan() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let client_id = client_id();

        let (id, status) = fakes.simulate_start_scan(&client_id, scan).await;

        assert_eq!(status.status, Phase::Requested);

        let status = fakes.simulate_stop_scan(&client_id, &id).await;

        assert_eq!(status.status, Phase::Stopped);
        Ok(())
    }

    #[tokio::test]
    async fn delete_scan_running() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let client_id = client_id();

        let (scan_id, _) = fakes.simulate_start_scan(&client_id, scan).await;

        let result = fakes
            .entry
            .delete_scans_id(fakes.internal_id(&client_id, &scan_id).await)
            .await;
        assert!(matches!(result, Err(DeleteScansIDError::Running)));
        Ok(())
    }

    #[tokio::test]
    async fn delete_scan() {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let (scan_id, _) = fakes.create_start_results(&client_id, scan).await;
        let result = fakes
            .entry
            .get_scans_id_results(scan_id.clone(), None, None);
        let result: Vec<_> = result.collect().await;

        let result: Vec<_> = result
            .into_iter()
            .filter_map(|x| x.ok())
            .map(|x| x.id)
            .collect();
        assert!(!result.is_empty(), "expected results");
        fakes.entry.delete_scans_id(scan_id.clone()).await.unwrap();
        let result = fakes
            .entry
            .get_scans_id_results(scan_id.clone(), None, None);
        let result: Vec<_> = result.collect().await;

        let result = result.len();
        assert_eq!(result, 0);
        let count: i64 = query_scalar("SELECT count(id) FROM client_scan_map WHERE id = ?")
            .bind(scan_id)
            .fetch_one(&fakes.entry.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn start_scan_succeeded() {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let (_, status) = fakes.create_start_results(&client_id, scan).await;

        let result = status.status;
        assert_eq!(result, Phase::Succeeded);
    }

    #[tokio::test]
    async fn get_scans() {
        let entry = Fakes::init().await.entry;
        for i in 0..10 {
            let scan = models::Scan {
                scan_id: i.to_string(),
                ..Default::default()
            };
            let client_id = if i % 2 == 0 {
                client_id()
            } else {
                second_client_id()
            };
            entry
                .post_scans(client_id, scan)
                .await
                .expect("post scans should succeed");
        }
        let result = entry.get_scans(client_id());

        assert_eq!(result.filter_map(async move |x| x.ok()).count().await, 5);
        let result = entry.get_scans(second_client_id());

        assert_eq!(result.filter_map(async move |x| x.ok()).count().await, 5);
        let result = entry.get_scans(ClientHash::from("third").to_string());
        assert_eq!(result.filter_map(async move |x| x.ok()).count().await, 0);
    }

    #[tokio::test]
    async fn get_scans_preferences() {
        let entry = Fakes::init().await.entry;
        let result = entry.get_scans_preferences().await;

        insta::assert_ron_snapshot!(result);
    }

    mod results {

        use super::*;

        #[tokio::test]
        async fn all() {
            let mut fakes = Fakes::init().await;
            let scan = fakes.success_scan();
            let (scan_id, _) = fakes.create_start_results(&client_id, scan).await;
            let result = fakes.entry.get_scans_id_results(scan_id, None, None);
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
            let (scan_id, _) = fakes.create_start_results(&client_id, scan).await;
            let result = fakes
                .entry
                .get_scans_id_results(scan_id.clone(), None, None);
            let all: Vec<_> = result.collect().await;
            let all: Vec<_> = all.into_iter().filter_map(|x| x.ok()).collect();
            let all = all.len();
            let check_subset = async |range: (Option<usize>, Option<usize>)| {
                let (start, end) = range;
                let results = fakes.entry.get_scans_id_results(scan_id, start, end);
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
            check_subset.clone()((Some(0), Some(5))).await;
            check_subset.clone()((Some(5), None)).await;
            check_subset.clone()((Some(5), Some(23))).await;
            check_subset.clone()((None, Some(69))).await;
            check_subset.clone()((Some(42), Some(4242))).await;
            check_subset.clone()((Some(4242), Some(10))).await;
        }

        #[tokio::test]
        async fn single_result() {
            let mut fakes = Fakes::init().await;
            let scan = fakes.success_scan();
            let (scan_id, _) = fakes.create_start_results(&client_id, scan).await;
            let result = fakes.entry.get_scans_id_results_id(scan_id, 42).await;
            let result = result.map(|x| x.id).unwrap();
            assert_eq!(result, 42)
        }
        #[tokio::test]
        async fn invalid_result_id() {
            let mut fakes = Fakes::init().await;
            let scan = fakes.success_scan();
            let (scan_id, _) = fakes.create_start_results(&client_id, scan).await;
            let result = fakes.entry.get_scans_id_results_id(scan_id, 4242).await;
            let result = result.map(|x| x.id);
            assert!(matches!(result, Err(GetScansIDResultsIDError::InvalidID)))
        }
    }
}
