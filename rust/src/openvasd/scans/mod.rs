use std::{num::ParseIntError, pin::Pin, str::FromStr, sync::Arc};

use futures::StreamExt;
use greenbone_scanner_framework::{entry::Prefixed, models::AliveTestMethods, prelude::*};
use scannerlib::{
    models::{FeedState, ResultType},
    scanner,
};
use sqlx::{Acquire, QueryBuilder, Row, SqlitePool, query, query_scalar, sqlite::SqliteRow};
use tokio::sync::mpsc::Sender;

use crate::{
    config::Config,
    crypt::{self, ChaCha20Crypt, Crypt, Encrypted},
};
mod scheduling;
pub struct Endpoints<E> {
    pool: SqlitePool,
    crypter: Arc<E>,
    scheduling: Sender<scheduling::Message>,
}

impl<T> Prefixed for Endpoints<T> {
    fn prefix(&self) -> &'static str {
        ""
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Unexpected error while serialization")]
    Serialization(serde_json::Error),
    #[error("Unexpected error while doing a DB operation")]
    Sqlx(sqlx::Error),
    #[error("Unexpected error while encrypting or decrypting")]
    Crypt(crypt::ParseError),
    #[error("Incorrect internal ID, expected an numeric value.")]
    ParseInt(#[from] ParseIntError),
}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::Serialization(value)
    }
}

impl From<crypt::ParseError> for Error {
    fn from(value: crypt::ParseError) -> Self {
        Error::Crypt(value)
    }
}

async fn scan_insert<C>(
    pool: &SqlitePool,
    crypter: &C,
    client: &str,
    scan: models::Scan,
) -> Result<String, Error>
where
    C: Crypt,
{
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;

    let row = query("INSERT INTO client_scan_map(client_id, scan_id) VALUES (?, ?)")
        .bind(client.to_string())
        .bind(&scan.scan_id)
        .execute(&mut *tx)
        .await?;

    let mapped_id = row.last_insert_rowid().to_string();
    let auth_data = {
        let bytes = serde_json::to_vec(&scan.target.credentials)?;
        let bytes = crypter.encrypt(bytes).await;
        bytes.to_string()
    };
    query("INSERT INTO scans (id, auth_data) VALUES (?, ?)")
        .bind(&mapped_id)
        .bind(auth_data)
        .execute(&mut *tx)
        .await?;
    if !scan.vts.is_empty() {
        let mut builder = QueryBuilder::new("INSERT OR REPLACE INTO vts (id, vt)");
        builder.push_values(&scan.vts, |mut b, vt| {
            b.push_bind(&mapped_id).push_bind(&vt.oid);
        });
        let query = builder.build();
        query.execute(&mut *tx).await?;
        let vt_params = scan
            .vts
            .iter()
            .flat_map(|x| x.parameters.iter().map(move |p| (&x.oid, p.id, &p.value)))
            .collect::<Vec<_>>();
        if !vt_params.is_empty() {
            let mut builder =
                QueryBuilder::new("INSERT INTO vt_parameters (id, vt, param_id, param_value)");

            builder.push_values(vt_params, |mut b, (oid, param_id, param_value)| {
                b.push_bind(&mapped_id)
                    .push_bind(oid)
                    .push_bind(param_id as i64)
                    .push_bind(param_value);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }
    }

    if !scan.target.hosts.is_empty() {
        let mut builder = QueryBuilder::new("INSERT INTO hosts (id, host)");
        builder.push_values(scan.target.hosts, |mut b, host| {
            b.push_bind(&mapped_id).push_bind(host);
        });
        let query = builder.build();
        query.execute(&mut *tx).await?;
    }

    if !scan.target.excluded_hosts.is_empty() {
        let mut builder = QueryBuilder::new(
            "INSERT INTO resolved_hosts (id, original_host, resolved_host, kind, scan_status)",
        );
        builder.push_values(scan.target.excluded_hosts, |mut b, host| {
            //TODO: check host if ip v4, v6, dns or oci ... for now it doesn't matter.
            b.push_bind(&mapped_id)
                .push_bind(host.clone())
                .push_bind(host)
                .push_bind("dns")
                .push_bind("excluded");
        });
        let query = builder.build();
        query.execute(&mut *tx).await?;
    }

    if !scan.target.ports.is_empty() {
        let mut builder = QueryBuilder::new("INSERT INTO ports (id, protocol, start, end) ");
        builder.push_values(
            scan.target
                .ports
                .into_iter()
                .flat_map(|port| port.range.into_iter().map(move |r| (port.protocol, r))),
            |mut b, (protocol, range)| {
                b.push_bind(&mapped_id)
                    .push_bind(match protocol {
                        None => "udp_tcp",
                        Some(models::Protocol::TCP) => "tcp",
                        Some(models::Protocol::UDP) => "udp",
                    })
                    .push_bind(range.start as i64)
                    .push_bind(range.end.map(|x| x as i64));
            },
        );
        let query = builder.build();

        query.execute(&mut *tx).await?;
    }
    let mut scan_preferences = scan.scan_preferences;
    if scan.target.reverse_lookup_unify.unwrap_or_default() {
        scan_preferences.push(models::ScanPreference {
            id: "target_reverse_lookup_unify".to_string(),
            value: "true".to_string(),
        });
    }
    if scan.target.reverse_lookup_only.unwrap_or_default() {
        scan_preferences.push(models::ScanPreference {
            id: "target_reverse_lookup_only".to_string(),
            value: "true".to_string(),
        });
    }

    if !scan_preferences.is_empty() {
        let mut builder = QueryBuilder::new("INSERT INTO preferences (id, key, value)");
        builder.push_values(scan_preferences, |mut b, pref| {
            b.push_bind(&mapped_id)
                .push_bind(pref.id)
                .push_bind(pref.value);
        });
        let query = builder.build();
        query.execute(&mut *tx).await?;
    }

    tx.commit().await?;
    Ok(scan.scan_id)
}

impl<E> PostScans for Endpoints<E>
where
    E: crate::crypt::Crypt + Sync + Send,
{
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send + '_>> {
        let annoying = scan.scan_id.clone();
        Box::pin(async move {
            tracing::debug!(client_id, ?scan);
            scan_insert(&self.pool, self.crypter.as_ref(), &client_id, scan)
                .await
                .map_err(|x| match x {
                    Error::Sqlx(sqlx::Error::Database(db))
                        if matches!(db.kind(), sqlx::error::ErrorKind::UniqueViolation)
                            && db.message().ends_with(
                                "client_scan_map.client_id, client_scan_map.scan_id",
                            ) =>
                    {
                        PostScansError::DuplicateId(annoying)
                    }
                    Error::Sqlx(error) => PostScansError::External(Box::new(error)),
                    Error::Serialization(error) => PostScansError::External(Box::new(error)),
                    Error::Crypt(error) => PostScansError::External(Box::new(error)),
                    Error::ParseInt(error) => PostScansError::External(Box::new(error)),
                })
        })
    }
}

impl<E> MapScanID for Endpoints<E>
where
    E: Send + Sync,
{
    fn contains_scan_id<'a>(
        &'a self,
        client_id: &'a str,
        scan_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
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

fn into_external_error<T>(value: T) -> GetScansError
where
    T: std::error::Error + Send + Sync + 'static,
{
    GetScansError::External(Box::new(value))
}

impl<E> GetScans for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans(&self, client_id: String) -> StreamResult<'static, String, GetScansError> {
        Box::new(
            query("SELECT scan_id FROM client_scan_map WHERE client_id = ?")
                .bind(client_id)
                .fetch(&self.pool)
                .map(|r| r.map(|r| r.get("scan_id")).map_err(into_external_error)),
        )
    }
}

impl<E> GetScansPreferences for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_preferences(
        &self,
    ) -> Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>> {
        Box::pin(async move { scanner::preferences::preference::PREFERENCES.to_vec() })
    }
}

async fn get_scan<C>(
    tx: &mut sqlx::SqliteConnection,
    crypter: &C,
    id: i64,
) -> Result<models::Scan, Error>
where
    C: Send + Sync + Crypt,
{
    fn rows_to_ports(ports: Vec<SqliteRow>) -> Vec<models::Port> {
        let mut tcp = Vec::with_capacity(ports.len());
        let mut udp = Vec::with_capacity(ports.len());
        let mut tcp_udp = Vec::with_capacity(ports.len());
        for row in ports {
            let protocol: String = row.get("protocol");
            let range = models::PortRange {
                start: row.get::<i64, _>("start") as usize,
                end: row.get::<Option<i64>, _>("end").map(|x| x as usize),
            };

            match &protocol as &str {
                "udp" => udp.push(range),
                "tcp" => tcp.push(range),
                _ => tcp_udp.push(range),
            }
        }
        vec![
            models::Port {
                protocol: Some(models::Protocol::TCP),
                range: tcp,
            },
            models::Port {
                protocol: Some(models::Protocol::UDP),
                range: udp,
            },
            models::Port {
                protocol: None,
                range: tcp_udp,
            },
        ]
    }
    let scan_row = query(
        r#"
        SELECT created_at, start_time, end_time, auth_data
        FROM scans
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let preferences = query(r#"SELECT key, value FROM preferences WHERE id = ?"#)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let preferences: Vec<models::ScanPreference> = preferences
        .into_iter()
        .map(|row| models::ScanPreference {
            id: row.get("key"),
            value: row.get("value"),
        })
        .collect();

    let ports = query("SELECT protocol, start, end FROM ports WHERE id = ? AND alive = 0")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    let ports = rows_to_ports(ports);

    let alive_test_ports =
        query("SELECT protocol, start, end FROM ports WHERE id = ? AND alive = 1")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    let alive_test_ports = rows_to_ports(alive_test_ports);

    let reverse_lookup_unify = preferences
        .iter()
        .any(|x| &x.id == "target_reverse_lookup_unify" && x.value.parse().unwrap_or_default());
    let reverse_lookup_only = preferences
        .iter()
        .any(|x| &x.id == "target_reverse_lookup_only" && x.value.parse().unwrap_or_default());

    let hosts: Vec<String> = query_scalar(r#"SELECT host FROM hosts WHERE id = ?"#)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;

    let oids = query_scalar("SELECT vt FROM vts WHERE id = ?")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;

    let mut vts = Vec::with_capacity(oids.len());
    for oid in oids {
        let parameters =
            query("SELECT param_id, param_value FROM vt_parameters WHERE id = ? AND vt = ?")
                .bind(id)
                .bind(&oid)
                .fetch_all(&mut *tx)
                .await?
                .iter()
                .map(|row| models::Parameter {
                    id: row.get("param_id"),
                    value: row.get("param_value"),
                })
                .collect();
        vts.push(models::VT { oid, parameters });
    }

    let alive_methods: Vec<String> = query_scalar("SELECT method FROM alive_methods WHERE id = ?")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;

    let alive_test_methods = alive_methods
        .iter()
        .map(|x| AliveTestMethods::from(x as &str))
        .collect::<Vec<_>>();
    let scan_id: String = query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

    let excluded_hosts = query_scalar("SELECT original_host FROM resolved_hosts WHERE id = ?")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;

    let auth_data = scan_row.get::<String, _>("auth_data");
    let encrypted: Encrypted = Encrypted::try_from(auth_data)?;
    let auth_data = crypter.decrypt(encrypted).await;
    let credentials = serde_json::from_slice::<Vec<models::Credential>>(&auth_data)?;

    let scan = models::Scan {
        scan_id,
        target: models::Target {
            hosts,
            ports,
            excluded_hosts,
            credentials,
            alive_test_ports,
            alive_test_methods,
            reverse_lookup_unify: if reverse_lookup_unify {
                Some(true)
            } else {
                None
            },
            reverse_lookup_only: if reverse_lookup_only {
                Some(true)
            } else {
                None
            },
        },
        scan_preferences: preferences,
        vts,
    };
    Ok(scan)
}

impl<E> Endpoints<E>
where
    E: Send + Sync + Crypt,
{
    async fn get_scan(&self, id: String) -> Result<models::Scan, Error> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let id = id.parse()?;
        let result = get_scan(&mut tx, self.crypter.as_ref(), id).await;
        tx.commit().await?;
        result
    }
}

impl<E> GetScansId for Endpoints<E>
where
    E: Send + Sync + Crypt,
{
    fn get_scans_id(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send + '_>> {
        Box::pin(async move { self.get_scan(id).await.map_err(into_external_error) })
    }
}
fn row_to_result(row: SqliteRow) -> models::Result {
    models::Result {
        id: row.get::<i64, _>("result_id") as usize,
        r_type: ResultType::from_str(row.get::<&str, _>("type"))
            .expect("stored type must be known"),

        ip_address: row.get("ip_address"),
        hostname: row.get("hostname"),
        oid: row.get("oid"),
        port: row.get("port"),
        protocol: match row.get::<&str, _>("protocol") {
            "udp" => Some(models::Protocol::UDP),
            "tcp" => Some(models::Protocol::TCP),
            _ => None,
        },
        message: row.get("message"),
        detail: row
            .get::<Option<String>, _>("detail_name")
            .map(|name| models::Detail {
                name,
                value: row
                    .get::<Option<String>, _>("detail_value")
                    .unwrap_or_default(),
                source: models::Source {
                    s_type: row
                        .get::<Option<String>, _>("source_type")
                        .unwrap_or_default(),
                    name: row
                        .get::<Option<String>, _>("source_name")
                        .unwrap_or_default(),
                    description: row
                        .get::<Option<String>, _>("source_description")
                        .unwrap_or_default(),
                },
            }),
    }
}
impl<E> GetScansIdResults for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<'static, models::Result, GetScansIDResultsError> {
        let q = match (from, to) {
            (None, None) => {
                r#"
SELECT id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
        detail_name, detail_value, 
        source_type, source_name, source_description
FROM results
WHERE id =  ?"#
            }
            (Some(_), None) => {
                r#"
SELECT id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
        detail_name, detail_value, 
        source_type, source_name, source_description
FROM results
WHERE id =  ?
AND result_id >= ?"#
            }
            (None, Some(_)) => {
                r#"
SELECT id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
        detail_name, detail_value, 
        source_type, source_name, source_description
FROM results
WHERE id =  ?
AND result_id <= ?"#
            }
            (Some(_), Some(_)) => {
                r#"
SELECT id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
        detail_name, detail_value, 
        source_type, source_name, source_description
FROM results
WHERE id =  ?
AND result_id <= ?
AND result_id >= ?"#
            }
        };
        let mut q = query(q).bind(id);
        if let Some(from) = from {
            q = q.bind(from as i64);
        }
        if let Some(to) = to {
            q = q.bind(to as i64);
        }

        Box::new(q.fetch(&self.pool).map(|r| {
            r.map(row_to_result)
                .map_err(|e| GetScansIDResultsError::External(Box::new(e)))
        }))
    }
}
impl<E> GetScansIdResultsId for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> Pin<Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send + '_>>
    {
        Box::pin(async move {
            let maybe_row = query(
                r#"
SELECT id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
        detail_name, detail_value, 
        source_type, source_name, source_description
FROM results
WHERE id =  ?
AND result_id = ?"#,
            )
            .bind(id)
            .bind(result_id as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(|x| GetScansIDResultsIDError::External(Box::new(x)))?;
            match maybe_row {
                Some(row) => Ok(row_to_result(row)),
                None => Err(GetScansIDResultsIDError::NotFound),
            }
        })
    }
}

async fn scan_get_status(pool: &SqlitePool, id: i64) -> Result<models::Status, sqlx::error::Error> {
    let scan_row = query(r#"
        SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status
        FROM scans
        WHERE id = ?
        "#).bind(id).fetch_one(pool).await?;
    let excluded = scan_row.get("host_excluded");
    let dead = scan_row.get("host_dead");
    let alive = scan_row.get("host_alive");
    let finished = excluded + dead + alive;
    let host_info = models::HostInfo {
        all: scan_row.get("host_all"),
        excluded,
        dead,
        alive,
        queued: scan_row.get("host_queued"),
        finished,
        scanning: None,
        remaining_vts_per_host: Default::default(),
    };
    let status = models::Status {
        start_time: scan_row.get("start_time"),
        end_time: scan_row.get("end_time"),
        // should never fail as we just allow parseable values to be stored in the DB
        status: scan_row.get::<String, _>("status").parse().unwrap(),
        host_info: Some(host_info),
    };

    Ok(status)
}

impl<E> GetScansIdStatus for Endpoints<E>
where
    E: Send + Sync,
{
    fn get_scans_id_status(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>>
    {
        Box::pin(async move {
            let id: i64 = id
                .parse()
                .map_err(|e| GetScansIDStatusError::External(Box::new(e)))?;
            scan_get_status(&self.pool, id)
                .await
                .map_err(|e| GetScansIDStatusError::External(Box::new(e)))
        })
    }
}
impl<E> PostScansId for Endpoints<E>
where
    E: Send + Sync,
{
    fn post_scans_id(
        &self,
        id: String,
        action: models::Action,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostScansIDError>> + Send + '_>> {
        Box::pin(async move {
            self.scheduling
                .send(match action {
                    models::Action::Start => scheduling::Message::Start(id),
                    models::Action::Stop => scheduling::Message::Stop(id),
                })
                .await
                .map_err(|e| PostScansIDError::External(Box::new(e)))
        })
    }
}
impl<E> DeleteScansId for Endpoints<E>
where
    E: Send + Sync,
{
    fn delete_scans_id(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send + '_>> {
        Box::pin(async move {
            // everything else should have ON DELETE CASCADE
            query("DELETE FROM client_scan_map WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| DeleteScansIDError::External(Box::new(e)))
                .map(|_| ())
        })
    }
}

pub(crate) fn config_to_crypt(config: &Config) -> ChaCha20Crypt {
    // unwrap_or_else is a safe guard in the case the db is stored on disk but no key is provided.
    // Otherwise the credentials can never be decrypted.
    config
        .storage
        .credential_key()
        .map(ChaCha20Crypt::new)
        .unwrap_or_else(|| ChaCha20Crypt::new("insecure"))
}

pub async fn init<F>(
    pool: SqlitePool,
    config: &Config,
    feed_state: F,
) -> Result<Endpoints<ChaCha20Crypt>, Box<dyn std::error::Error + Send + Sync>>
where
    F: Fn() -> Pin<Box<dyn Future<Output = FeedState> + Send + 'static>> + Send + 'static,
{
    let crypter = Arc::new(config_to_crypt(config));
    let scheduler_sender =
        scheduling::init(pool.clone(), crypter.clone(), feed_state, config).await?;
    Ok(Endpoints {
        pool,
        crypter,
        scheduling: scheduler_sender,
    })
}

#[cfg(test)]
mod tests {
    use std::{pin::Pin, sync::Arc, time::Duration};

    use futures::StreamExt;
    use greenbone_scanner_framework::{
        GetScans, GetScansId, GetScansIdResults, GetScansIdStatus, GetScansPreferences, MapScanID,
        PostScans, PostScansError,
        models::{
            self, AliveTestMethods, Credential, CredentialType, PrivilegeInformation,
            ScanPreference, Service,
        },
        prelude::PostScansId,
    };
    use scannerlib::{
        models::{FeedState, Phase},
        scanner,
    };
    use sqlx::SqlitePool;

    use crate::{
        config::Config,
        crypt::ChaCha20Crypt,
        scans::{config_to_crypt, scheduling},
    };

    fn feed_state() -> Pin<Box<dyn Future<Output = FeedState> + Send + 'static>> {
        Box::pin(async { FeedState::Synced("0".into(), "2".into()) })
    }
    async fn init(pool: SqlitePool, config: &Config) -> super::Endpoints<ChaCha20Crypt> {
        super::init(pool, config, feed_state).await.unwrap()
    }

    fn generate_hosts() -> Vec<Vec<String>> {
        vec![vec![], vec!["0".into()]]
    }
    fn generate_excluded_hosts() -> Vec<Vec<String>> {
        vec![vec![], vec!["1".into()]]
    }

    fn generate_ports() -> Vec<Vec<models::Port>> {
        vec![
            vec![],
            vec![
                models::Port {
                    protocol: None,
                    range: vec![],
                },
                models::Port {
                    protocol: None,
                    range: vec![
                        models::PortRange {
                            start: 22,
                            end: None,
                        },
                        models::PortRange {
                            start: 22,
                            end: Some(23),
                        },
                    ],
                },
                models::Port {
                    protocol: Some(models::Protocol::TCP),
                    range: vec![models::PortRange {
                        start: 42,
                        end: None,
                    }],
                },
                models::Port {
                    protocol: Some(models::Protocol::UDP),
                    range: vec![models::PortRange {
                        start: 69,
                        end: None,
                    }],
                },
            ],
        ]
    }

    fn all_services() -> Vec<Service> {
        vec![
            Service::SSH,
            Service::SMB,
            Service::ESXi,
            Service::SNMP,
            Service::KRB5,
        ]
    }

    fn all_ports() -> Vec<Option<u16>> {
        vec![None, Some(22)]
    }

    fn sample_privileges() -> Vec<Option<PrivilegeInformation>> {
        vec![
            None,
            Some(PrivilegeInformation {
                username: "priv_user".to_string(),
                password: "priv_pass".to_string(),
            }),
        ]
    }

    fn all_credential_types_for_service(service: &Service) -> Vec<CredentialType> {
        match service {
            Service::SSH => {
                let mut creds = Vec::new();
                for privilege in sample_privileges() {
                    creds.push(CredentialType::UP {
                        username: "root".to_string(),
                        password: "password".to_string(),
                        privilege: privilege.clone(),
                    });
                    creds.push(CredentialType::USK {
                        username: "root".to_string(),
                        password: Some("keypass".to_string()),
                        private_key: "private_key_data".to_string(),
                        privilege: privilege.clone(),
                    });
                    creds.push(CredentialType::USK {
                        username: "root".to_string(),
                        password: None,
                        private_key: "private_key_data".to_string(),
                        privilege: privilege.clone(),
                    });
                }
                creds
            }
            Service::SMB | Service::ESXi => {
                vec![CredentialType::UP {
                    username: "admin".to_string(),
                    password: "adminpass".to_string(),
                    privilege: None,
                }]
            }
            Service::SNMP => vec![CredentialType::SNMP {
                username: "snmpuser".to_string(),
                password: "snmppass".to_string(),
                community: "public".to_string(),
                auth_algorithm: "SHA".to_string(),
                privacy_password: "privpass".to_string(),
                privacy_algorithm: "AES".to_string(),
            }],
            Service::KRB5 => vec![CredentialType::KRB5 {
                username: "krbuser".to_string(),
                password: "krbpass".to_string(),
                realm: "EXAMPLE.COM".to_string(),
                kdc: "kdc.example.com".to_string(),
            }],
            Service::Generic => vec![CredentialType::UP {
                username: "moep".into(),
                password: "moep".into(),
                privilege: None,
            }],
        }
    }

    fn generate_credentials() -> Vec<Credential> {
        itertools::iproduct!(all_services().into_iter(), all_ports().into_iter())
            .flat_map(|(s, p)| {
                all_credential_types_for_service(&s)
                    .into_iter()
                    .map(move |c| (s.clone(), p, c))
            })
            .map(|(service, port, credential_type)| Credential {
                service,
                port,
                credential_type,
            })
            .collect()
    }

    fn generate_alive_test_methods() -> Vec<AliveTestMethods> {
        use AliveTestMethods::*;
        vec![TcpAck, Icmp, Arp, ConsiderAlive, TcpSyn]
    }

    fn generate_targets() -> Vec<models::Target> {
        itertools::iproduct!(
            generate_hosts(),
            generate_ports(),
            generate_excluded_hosts(),
            generate_ports()
        )
        .map(
            |(hosts, ports, excluded_hosts, alive_test_ports)| models::Target {
                hosts,
                ports,
                excluded_hosts,
                credentials: generate_credentials(),
                alive_test_ports,
                alive_test_methods: generate_alive_test_methods(),
                reverse_lookup_unify: None,
                reverse_lookup_only: Some(true),
            },
        )
        .collect()
    }

    fn generate_scan_prefs() -> Vec<ScanPreference> {
        vec![ScanPreference {
            id: "moep".into(),
            value: "narf".into(),
        }]
    }

    fn generate_vts() -> Vec<models::VT> {
        vec![
            models::VT {
                oid: "0".into(),
                parameters: vec![],
            },
            models::VT {
                oid: "1".into(),
                parameters: vec![models::Parameter {
                    id: 0,
                    value: "aha".to_string(),
                }],
            },
        ]
    }

    pub fn generate_scan() -> Vec<models::Scan> {
        let discovery = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/openvasd/discovery.json"
        ));
        let mut discovery: models::Scan = serde_json::from_slice(discovery).unwrap();
        discovery.scan_id = "discovery".to_string();
        let simple_auth_ssh_scan = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/openvasd/simple_auth_ssh_scan.json"
        ));
        let mut simple_auth_ssh_scan: models::Scan =
            serde_json::from_slice(simple_auth_ssh_scan).unwrap();
        simple_auth_ssh_scan.scan_id = "simple_auth_ssh_scan".to_string();

        let mut results = vec![simple_auth_ssh_scan, discovery];
        results.extend(generate_targets().into_iter().map(|target| models::Scan {
            scan_id: uuid::Uuid::new_v4().to_string(),
            target,
            scan_preferences: generate_scan_prefs(),
            vts: generate_vts(),
        }));
        results
    }

    pub async fn create_pool() -> crate::Result<(Config, SqlitePool)> {
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
            ..Default::default()
        };

        let pool = crate::setup_sqlite(&config).await?;

        Ok((config, pool))
    }

    #[tokio::test]
    async fn post_scan() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;

        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        for scan in generate_scan() {
            let id = scan.scan_id.clone();
            let result = undertest.post_scans(client_id.clone(), scan).await.unwrap();
            assert_eq!(id, result);
        }

        Ok(())
    }

    #[tokio::test]
    async fn post_scan_duplicate_id() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            let id = scan.scan_id.clone();
            let result = undertest.post_scans(client_id.clone(), scan).await;
            assert!(result.is_ok(), "scan must be successfully added");
            assert_eq!(id, result.unwrap());
        }
        for scan in scans {
            let result = undertest.post_scans(client_id.clone(), scan).await;
            assert!(
                matches!(result, Err(PostScansError::DuplicateId(_))),
                "scan must be declined"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn map_id() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        for scan in scans {
            let result = undertest.contains_scan_id(&client_id, &scan.scan_id).await;
            assert!(result.is_some(), "scan must be found");
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scan_id() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        for scan in scans {
            let result = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();
            let result = undertest.get_scans_id(result).await?;
            assert_eq!(scan.scan_id, result.scan_id);
            assert_eq!(
                scan.target.credentials.len(),
                result.target.credentials.len()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scans_preferences() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let result = undertest.get_scans_preferences().await;
        assert_eq!(
            result,
            scanner::preferences::preference::PREFERENCES.to_vec()
        );

        Ok(())
    }

    #[tokio::test]
    async fn get_scan_id_status() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;

        let crypter = Arc::new(config_to_crypt(&config));
        let scheduler_sender = scheduling::init_with_scanner(
            pool.clone(),
            crypter.clone(),
            &config,
            scheduling::tests::scanner_succeeded().build(),
        )
        .await?;
        let undertest = super::Endpoints {
            pool,
            crypter,
            scheduling: scheduler_sender,
        };

        let client_id = "moep".to_string();
        let scans = generate_scan();
        assert!(!scans.is_empty());
        for scan in scans.clone() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        for scan in scans.iter() {
            let result = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();
            let result = undertest.get_scans_id_status(result).await?;
            assert_eq!(result.status, Phase::Stored);
        }
        for scan in scans.iter() {
            let id = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();

            undertest
                .post_scans_id(id.clone(), models::Action::Start)
                .await?;
            let mut status;
            loop {
                status = undertest.get_scans_id_status(id.clone()).await?;
                if status.is_running() {
                    break;
                }
            }
            assert!(matches!(status.status, Phase::Requested | Phase::Running));
        }
        for scan in scans.iter() {
            let id = undertest
                .contains_scan_id(&client_id, &scan.scan_id)
                .await
                .unwrap();

            undertest
                .post_scans_id(id.clone(), models::Action::Start)
                .await?;
            let mut status;
            loop {
                status = undertest.get_scans_id_status(id.clone()).await?;
                if status.is_done() {
                    break;
                }
            }
            assert!(matches!(status.status, Phase::Succeeded));
            let result = undertest
                .get_scans_id_results(id.clone(), None, None)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 2);
            let result = undertest
                .get_scans_id_results(id.clone(), Some(1), None)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scans_id_results(id.clone(), None, Some(0))
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scans_id_results(id.clone(), Some(0), Some(0))
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.into_iter().filter_map(|x| x.ok()).count(), 1);
            let result = undertest
                .get_scans_id_results(id, Some(23), None)
                .collect::<Vec<_>>()
                .await;
            assert_eq!(result.len(), 0);
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_scans() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let undertest = init(pool, &config).await;
        let client_id = "moep".to_string();
        let scans = generate_scan();
        for scan in generate_scan() {
            undertest.post_scans(client_id.clone(), scan).await?;
        }
        let client_ids = undertest.get_scans(client_id).collect::<Vec<_>>().await;
        assert_eq!(client_ids.iter().filter(|x| x.is_err()).count(), 0);
        assert_eq!(client_ids.iter().filter(|x| x.is_ok()).count(), scans.len());
        let client_ids = undertest
            .get_scans("notme".to_string())
            .collect::<Vec<_>>()
            .await;
        assert!(client_ids.is_empty());

        Ok(())
    }
}
