use std::{pin::Pin, str::FromStr};

use futures::StreamExt;
use greenbone_scanner_framework::{
    MapScanID, StreamResult,
    entry::Prefixed,
    models::{HostInfo, PreferenceValue, ScanPreferenceInformation},
    prelude::*,
};
use sqlx::{Acquire, QueryBuilder, Row, SqlitePool, query, sqlite::SqliteRow};
use tokio::sync::mpsc::Sender;

use crate::container_image_scanner::scheduling;

pub struct Scans {
    pub pool: SqlitePool,
    pub scheduling: Sender<scheduling::Message>,
}

impl Prefixed for Scans {
    fn prefix(&self) -> &'static str {
        "container-image-scanner"
    }
}

impl Scans {
    async fn insert_scan(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Result<String, sqlx::error::Error> {
        let scan_id = scan.scan_id;
        tracing::debug!(client_id, scan_id, "creating scan");
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let row = query(
            r#"
            INSERT INTO client_scan_map(scan_id, client_id) VALUES (?, ?)
            "#,
        )
        .bind(&scan_id)
        .bind(&client_id)
        .execute(&mut *tx)
        .await?;
        let id = row.last_insert_rowid();
        let _ = query("INSERT INTO scans(id) VALUES (?)")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tracing::trace!(id, "inserted scan");

        if !scan.target.hosts.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO registry (id, host) ");
            builder.push_values(scan.target.hosts, |mut b, registry| {
                b.push_bind(id).push_bind(registry);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }
        if !scan.target.credentials.is_empty() {
            let mut builder =
                QueryBuilder::new("INSERT INTO credentials (id, username, password) ");
            builder.push_values(
                scan.target
                    .credentials
                    .iter()
                    .filter_map(|c| match &c.credential_type {
                        models::CredentialType::UP {
                            username,
                            password,
                            privilege: _,
                        } => Some((username, password)),
                        _ => None,
                    }),
                |mut b, (username, password)| {
                    b.push_bind(id).push_bind(username).push_bind(password);
                },
            );
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }
        if !scan.scan_preferences.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO preferences (id, key, value) ");
            builder.push_values(scan.scan_preferences, |mut b, pref| {
                b.push_bind(id).push_bind(pref.id).push_bind(pref.value);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(scan_id)
    }
}

impl PostScans for Scans {
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send + '_>> {
        Box::pin(async move {
            // maybe get rid of clone
            let scan_id = scan.scan_id.clone();
            self.insert_scan(client_id, scan)
                .await
                .map_err(|x| match x {
                    sqlx::Error::Database(be)
                        if be.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                    {
                        PostScansError::DuplicateId(scan_id)
                    }
                    err => PostScansError::from_external(err),
                })
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
            match query("SELECT id FROM client_scan_map WHERE client_id = ? AND scan_id = ?")
                .bind(client_id)
                .bind(scan_id)
                .fetch_optional(&self.pool)
                .await
            {
                Ok(x) => x.map(|r| r.get::<i64, _>("id")).map(|x| x.to_string()),
                Err(error) => {
                    tracing::warn!(%error, "Unable to fetch id from client_scan_map. Returning no id found.");
                    None
                }
            }
        })
    }
}

impl GetScans for Scans {
    fn get_scans(&self, client_id: String) -> StreamResult<'static, String, GetScansError> {
        let result = query(
            r#"
                SELECT scan_id FROM client_scan_map WHERE client_id = ?
            "#,
        )
        .bind(client_id)
        .fetch(&self.pool)
        .map(|x| {
            x.map(|x| x.get::<String, _>("scan_id"))
                .map_err(GetScansError::from_external)
        });
        Box::new(result)
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

impl Scans {
    async fn get_scan(pool: SqlitePool, id: String) -> Result<models::Scan, sqlx::error::Error> {
        let mut conn = pool.acquire().await?;
        let hosts: Vec<(String,)> = sqlx::query_as("SELECT host FROM registry WHERE id = ?")
            .bind(&id)
            .fetch_all(&mut *conn)
            .await?;
        let creds: Vec<(String, String)> =
            sqlx::query_as("SELECT username, password FROM credentials WHERE id = ?")
                .bind(&id)
                .fetch_all(&mut *conn)
                .await?;

        let preferences: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM preferences WHERE id = ?")
                .bind(&id)
                .fetch_all(&mut *conn)
                .await?;
        let scan_id = sqlx::query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
            .bind(&id)
            .fetch_one(&mut *conn)
            .await?;

        Ok(models::Scan {
            scan_id,
            target: models::Target {
                hosts: hosts.into_iter().map(|(h,)| h).collect(),
                credentials: creds
                    .into_iter()
                    .map(|(u, p)| models::Credential {
                        credential_type: models::CredentialType::UP {
                            username: u,
                            password: p,
                            privilege: None,
                        },
                        service: models::Service::Generic,
                        port: None,
                    })
                    .collect(),
                ..Default::default()
            },
            scan_preferences: preferences
                .into_iter()
                .map(|(id, value)| models::ScanPreference { id, value })
                .collect(),
            ..Default::default()
        })
    }
}

impl GetScansId for Scans {
    fn get_scans_id(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            Scans::get_scan(pool, id)
                .await
                .map_err(GetScansIDError::from_external)
        })
    }
}

fn row_to_result(row: SqliteRow) -> models::Result {
    let detail = match (
        row.try_get::<Option<String>, _>("detail_name")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("detail_value")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("source_type")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("source_name")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("source_description")
            .unwrap_or(None),
    ) {
        (Some(name), Some(value), Some(s_type), Some(name_src), Some(description)) => {
            Some(models::Detail {
                name,
                value,
                source: models::Source {
                    s_type,
                    name: name_src,
                    description,
                },
            })
        }
        _ => None,
    };
    let r_type = row
        .get::<String, _>("type")
        .parse::<models::ResultType>()
        .unwrap_or_default();

    models::Result {
        id: row.get::<i64, _>("id") as usize,
        r_type,
        ip_address: row
            .try_get::<Option<String>, _>("ip_address")
            .unwrap_or(None),
        hostname: row.try_get::<Option<String>, _>("hostname").unwrap_or(None),
        oid: row.try_get::<Option<String>, _>("oid").unwrap_or(None),
        port: row.try_get::<Option<i16>, _>("port").unwrap_or(None),
        protocol: row
            .try_get::<Option<String>, _>("protocol")
            .unwrap_or(None)
            .and_then(|s| s.parse::<models::Protocol>().ok()),
        message: row.try_get::<Option<String>, _>("message").unwrap_or(None),
        detail,
    }
}

impl GetScansIdResults for Scans {
    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<'static, models::Result, GetScansIDResultsError> {
        const SQL_BASE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ?
"#;

        const SQL_BASE_AND_GTE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id >= ?
"#;

        const SQL_BASE_AND_LTE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id <= ?
"#;

        const SQL_BASE_AND_GTE_LTE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id >= ? AND id <= ?
"#;

        let sql: &'static str = match (from, to) {
            (None, None) => SQL_BASE,
            (Some(_), None) => SQL_BASE_AND_GTE,
            (None, Some(_)) => SQL_BASE_AND_LTE,
            (Some(_), Some(_)) => SQL_BASE_AND_GTE_LTE,
        };
        let mut query = sqlx::query(sql).bind(id);

        if let Some(from_id) = from {
            query = query.bind(from_id as i64);
        }
        if let Some(to_id) = to {
            query = query.bind(to_id as i64);
        }

        let result = query.fetch(&self.pool).map(|x| {
            x.map(row_to_result)
                .map_err(GetScansIDResultsError::from_external)
        });
        Box::new(result)
    }
}

impl GetScansIdResultsId for Scans {
    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> Pin<Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send + '_>>
    {
        const SQL: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id = ?
"#;

        Box::pin(async move {
            query(SQL)
                .bind(&id)
                .bind(result_id as i64)
                .fetch_one(&self.pool)
                .await
                .map(row_to_result)
                .map_err(|x| match x {
                    sqlx::Error::RowNotFound => GetScansIDResultsIDError::InvalidID,
                    x => x.into(),
                })
        })
    }
}

fn row_to_status(row: SqliteRow) -> models::Status {
    let status = models::Phase::from_str(&row.get::<String, _>("status"))
        .expect("expact status to be a valid phase");
    let host_info = HostInfo {
        all: row.get("host_all"),
        alive: row.get("host_alive"),
        dead: row.get("host_dead"),
        queued: row.get("host_queued"),
        finished: row.get("host_finished"),
        ..Default::default()
    };

    models::Status {
        start_time: row.get::<Option<u64>, _>("start_time"),
        end_time: row.get::<Option<u64>, _>("end_time"),
        status,
        host_info: Some(host_info),
    }
}

impl GetScansIdStatus for Scans {
    fn get_scans_id_status(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>>
    {
        const SQL: &str = r#"SELECT start_time, end_time, status, host_all, host_alive, host_dead, host_queued, host_finished 
                FROM scans 
                WHERE id = ? "#;
        Box::pin(async move {
            query(SQL)
                .bind(&id)
                .fetch_one(&self.pool)
                .await
                .map(row_to_status)
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

    use super::Scans;
    use crate::{
        container_image_scanner::{
            Config, MIGRATOR,
            config::DBLocation,
            image::{
                DockerRegistryV2, DockerRegistryV2Mock, RegistrySetting, extractor::filtered_image,
                packages::AllTypes,
            },
            scheduling::Scheduler,
        },
        notus::path_to_products,
    };

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

        // TODO: get rid of arc
        let (sender, scheduler) = Scheduler::<R, E>::init(
            config.into(),
            Arc::new(pool.clone()),
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
        pub async fn init() -> Self {
            let registry =
                DockerRegistryV2Mock::serve_images(DockerRegistryV2Mock::supported_images()).await;
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
            let scan_id = self.entry.post_scans(client_id(), scan).await.unwrap();
            let id = self
                .entry
                .contains_scan_id(&client_id(), &scan_id)
                .await
                .unwrap();

            self.entry
                .post_scans_id(id, models::Action::Start)
                .await
                .unwrap();
            self.scheduler.check_for_message().await;

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
            for _ in 0..scans {
                Scheduler::<DockerRegistryV2, filtered_image::Extractor>::start_scans::<AllTypes>(
                    self.scheduler.config(),
                    self.scheduler.pool(),
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
        let scan_id = fakes.entry.post_scans(client_id(), scan).await?;
        let id = fakes
            .entry
            .contains_scan_id(&client_id(), &scan_id)
            .await
            .unwrap();

        fakes
            .entry
            .post_scans_id(id.clone(), models::Action::Start)
            .await?;
        fakes.scheduler.check_for_message().await;
        let status = fakes.entry.get_scans_id_status(id).await?;
        assert_eq!(status.status, Phase::Requested);
        Ok(())
    }

    #[tokio::test]
    async fn stop_scan() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let scan_id = fakes.entry.post_scans(client_id(), scan).await?;
        let id = fakes
            .entry
            .contains_scan_id(&client_id(), &scan_id)
            .await
            .unwrap();
        fakes
            .entry
            .post_scans_id(id.clone(), models::Action::Start)
            .await?;
        fakes.scheduler.check_for_message().await;
        let status = fakes.entry.get_scans_id_status(id.clone()).await?;

        assert_eq!(status.status, Phase::Requested);
        fakes
            .entry
            .post_scans_id(id.clone(), models::Action::Stop)
            .await
            .expect("post_scans_id must function");
        fakes.scheduler.check_for_message().await;
        let status = fakes
            .entry
            .get_scans_id_status(id.clone())
            .await
            .expect("get_scans_id_status must function");
        assert_eq!(status.status, Phase::Stopped);
        Ok(())
    }

    #[tokio::test]
    async fn delete_scan_running() -> Result<(), Box<dyn std::error::Error>> {
        let mut fakes = Fakes::init().await;
        let scan = fakes.success_scan();
        let scan_id = fakes.entry.post_scans(client_id(), scan).await?;
        let id = fakes
            .entry
            .contains_scan_id(&client_id(), &scan_id)
            .await
            .unwrap();
        fakes
            .entry
            .post_scans_id(id.clone(), models::Action::Start)
            .await?;
        fakes.scheduler.check_for_message().await;

        let result = fakes.entry.delete_scans_id(id.clone()).await;
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

            let result: Vec<_> = result
                .into_iter()
                .filter_map(|x| x.ok())
                .map(|x| x.id)
                .collect();
            assert_eq!(result.len(), 275 * fakes.success_scan().target.hosts.len());
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
