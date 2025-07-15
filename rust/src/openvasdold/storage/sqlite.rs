// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::BTreeMap, io::BufReader, str::FromStr, sync::RwLock, time::Duration};

use crate::crypt::Encrypted;

use super::*;
use futures::{StreamExt, TryFutureExt, TryStreamExt};
use itertools::Itertools;
use scannerlib::{
    models::{self, AliveTestMethods},
    notus,
    scanner::preferences::{self, preference::ScanPrefs},
    storage::{
        self, Retriever,
        inmemory::OIDs,
        items::nvt::{Feed, NvtPreference, NvtRef, PreferenceType, TagKey, TagValue},
    },
};
use sqlx::{Acquire, Database, SqlitePool, query::Query, query_scalar, sqlite::SqliteArguments};
use sqlx::{QueryBuilder, Row};
use sqlx::{Sqlite, sqlite::SqliteRow};
use sqlx::{query, query_with};
use tokio::task::JoinSet;

#[derive(Clone, Debug, Default)]
struct Progress {
    /// The scan that is being tracked. The credentials passwords are encrypted.
    scan: models::Scan,
    /// The status of the scan. Does not need to be encrypted.
    status: models::Status,
    /// The results of the scan as encrypted json.
    ///
    /// The reason that it is json is that we don't need it unless it is requested by the user.
    results: Vec<crypt::Encrypted>,
}

#[derive(Debug)]
pub struct Storage<E> {
    crypter: Arc<E>,
    pool: sqlx::Pool<sqlx::Sqlite>,

    //TODO: remove script_storage by implementing it here when InMemoryStorage and FileStorage are
    //removed
    script_storage: Arc<scannerlib::storage::inmemory::InMemoryStorage>,
}

type Q<'a> = Query<'a, Sqlite, <Sqlite as Database>::Arguments<'a>>;

impl<E> Storage<E> where E: crate::crypt::Crypt + Send + Sync + 'static {}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::RowNotFound => Self::NotFound,
            _ => Self::Storage(Box::new(value)),
        }
    }
}

#[async_trait]
impl<E> ScanStorer for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn insert_scan(&self, scan: models::Scan) -> Result<(), Error> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let mapped_id = query("SELECT id FROM client_scan_map WHERE scan_id = ?")
            .bind(&scan.scan_id)
            .fetch_one(&mut *tx)
            .await
            .map(|row| row.get::<i64, _>("id"))?;
        let auth_data = {
            if !scan.target.credentials.is_empty() {
                let bytes = serde_json::to_vec(&scan.target.credentials)
                    .map_err(|_| Error::Serialization)?;
                let bytes = self.crypter.encrypt(bytes).await;
                Some(bytes.to_string())
            } else {
                None
            }
        };
        query("INSERT INTO scans (id, auth_data) VALUES (?, ?)")
            .bind(mapped_id)
            .bind(auth_data)
            .execute(&mut *tx)
            .await?;
        if !scan.vts.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO vts (id, vt)");
            builder.push_values(&scan.vts, |mut b, vt| {
                b.push_bind(mapped_id).push_bind(&vt.oid);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
            let mut builder =
                QueryBuilder::new("INSERT INTO vt_parameters (id, vt, param_id, param_value)");
            builder.push_values(
                scan.vts
                    .iter()
                    .flat_map(|x| x.parameters.iter().map(move |p| (&x.oid, p.id, &p.value))),
                |mut b, (oid, param_id, param_value)| {
                    b.push_bind(mapped_id)
                        .push_bind(oid)
                        .push_bind(param_id as i64)
                        .push_bind(param_value);
                },
            );
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }

        if !scan.target.hosts.is_empty() {
            let mut builder = QueryBuilder::new("INSERT INTO hosts (id, host)");
            builder.push_values(scan.target.hosts, |mut b, host| {
                b.push_bind(mapped_id).push_bind(host);
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
                b.push_bind(mapped_id)
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
                    b.push_bind(mapped_id)
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
        let mut scan_preferences = scan.scan_preferences.0;
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
                b.push_bind(mapped_id)
                    .push_bind(pref.id)
                    .push_bind(pref.value);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn remove_scan(&self, id: &str) -> Result<(), Error> {
        query("DELETE FROM client_scan_map WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_status(&self, id: &str, status: models::Status) -> Result<(), Error> {
        tracing::debug!(id, status = %status.status, "Set status.");
        let host_info = status.host_info.unwrap_or_default();
        let _ = query(
            r#"
        UPDATE scans SET
            start_time = ?,
            end_time = ?,
            host_dead = ?,
            host_alive = ?,
            host_queued = ?,
            host_excluded = ?,
            host_all = ?,
            status = ?
        WHERE id = ?"#,
        )
        .bind(status.start_time.map(|x| x as i64))
        .bind(status.end_time.map(|x| x as i64))
        .bind(host_info.dead as i64)
        .bind(host_info.alive as i64)
        .bind(host_info.queued as i64)
        .bind(host_info.excluded as i64)
        .bind(host_info.all as i64)
        .bind(status.status.to_string())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl<E> AppendFetchResult for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn append_fetched_result(
        &self,
        kind: ScanResultKind,
        mut results: ScanResults,
    ) -> Result<(), Error> {
        if !results.results.is_empty() {
            // TODO: get latest result_id and double check first id to be expected
            //
            QueryBuilder::new(
                r#"INSERT INTO results (
                    id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
                    detail_name, detail_value, 
                    source_type, source_name, source_description
                )"#,
            )
            .push_values(results.results, |mut b, result| {
                b.push_bind(&results.id)
                    .push_bind(result.id as i64)
                    .push_bind(result.r_type.to_string())
                    .push_bind(result.ip_address)
                    .push_bind(result.hostname)
                    .push_bind(result.oid)
                    .push_bind(result.port)
                    .push_bind(result.protocol.map(|p| p.to_string()))
                    .push_bind(result.message)
                    .push_bind(result.detail.as_ref().map(|d| d.name.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.value.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.source.s_type.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.source.name.clone()))
                    .push_bind(result.detail.as_ref().map(|d| d.source.description.clone()));
            })
            .build()
            .execute(&self.pool)
            .await?;
        }

        let status = match &kind {
            ScanResultKind::StatusOverride => results.status,
            // TODO: refactor on StatusAddition to do that within SQL directly instead of get mut
            ScanResultKind::StatusAddition => {
                let previous_status = self.get_status(&results.id).await?;
                results.status.update_with(&previous_status);
                results.status
            }
        };
        self.update_status(&results.id, status).await?;
        Ok(())
    }
}

#[async_trait]
impl<E> ProgressGetter for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    //TODO: delete, that verification needs to be done in the storage while storing the scan
    async fn get_scan_ids(&self) -> Result<Vec<String>, Error> {
        let scan_ids = sqlx::query_scalar("SELECT scan_id FROM client_scan_map")
            .fetch_all(&self.pool)
            .await?;
        Ok(scan_ids)
    }

    async fn get_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
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
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let scan_row = query(r#"
        SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status, auth_data
        FROM scans
        WHERE id = ?
        "#).bind(id).fetch_one(&mut *tx).await?;
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
            status: scan_row
                .get::<String, _>("status")
                .parse()
                .map_err(|_| Error::Serialization)?,
            host_info: Some(host_info),
        };
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

        // narf
        let scan_preferences = ScanPrefs(preferences);

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

        let alive_methods: Vec<String> =
            query_scalar("SELECT method FROM alive_methods WHERE id = ?")
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

        let credentials = if let Some(auth_data) = scan_row.get::<Option<String>, _>("auth_data") {
            let encrypted: Encrypted = Encrypted::try_from(auth_data)?;
            let auth_data = self.crypter.decrypt(encrypted).await;
            serde_json::from_slice::<Vec<models::Credential>>(&auth_data)?
        } else {
            vec![]
        };

        let scan = models::Scan {
            scan_id,
            target: models::Target {
                hosts,
                ports,
                excluded_hosts,
                credentials,
                alive_test_ports,
                alive_test_methods,
                // TODO: that needs to be changed
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
            scan_preferences,
            vts,
        };
        Ok((scan, status))
    }

    async fn get_decrypted_scan(&self, id: &str) -> Result<(models::Scan, models::Status), Error> {
        self.get_scan(id).await
    }

    async fn get_status(&self, id: &str) -> Result<models::Status, Error> {
        // TODO: refactor with get_scans
        let scan_row = query(r#"
        SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status, auth_data
        FROM scans
        WHERE id = ?
        "#).bind(id).fetch_one(&self.pool).await?;
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
            status: scan_row
                .get::<String, _>("status")
                .parse()
                .map_err(|_| Error::Serialization)?,
            host_info: Some(host_info),
        };

        Ok(status)
    }

    async fn get_results(
        &self,
        id: &str,
        from: Option<usize>,
        to: Option<usize>,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>, Error> {
        let mut query = QueryBuilder::new(
            r#"SELECT id, result_id, type, ip_address, hostname, oid, port, protocol, message, 
                        detail_name, detail_value, 
                        source_type, source_name, source_description
                FROM results
                WHERE id = "#,
        );
        query.push_bind(id);

        if let Some(from) = from {
            query.push("AND result_id > ");
            query.push_bind(from as i64);
        }
        if let Some(to) = to {
            query.push("AND result_id < ");
            query.push_bind(to as i64);
        }
        let results = query.build().fetch_all(&self.pool).await?;
        let results = results
            .into_iter()
            .map(|row| models::Result {
                id: row.get::<i64, _>("result_id") as usize,
                r_type: row.get::<String, _>("type").into(),
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
            })
            .map(|result| serde_json::to_vec(&result))
            .filter_map(|x| x.ok());

        Ok(Box::new(results))
    }
}

fn from_config_to_sqlite_address(config: &Config) -> String {
    use crate::config::StorageType;

    match config.storage.storage_type {
        StorageType::InMemory => "sqlite::memory:?cache=shared".to_owned(),
        StorageType::FileSystem if config.storage.fs.path.is_dir() => {
            let mut p = config.storage.fs.path.clone();
            p.push("openvasd.db");
            format!("sqlite:{}", p.to_string_lossy())
        }
        StorageType::FileSystem => format!("sqlite:{}", config.storage.fs.path.to_string_lossy()),
        StorageType::Redis => unreachable!(
            "Redis configuration should never call storage::sqlite::Storage::from_config_and_feeds"
        ),
    }
}

#[async_trait]
impl<E> ScanIDClientMapper for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static + Default,
{
    async fn generate_mapped_id(
        &self,
        client: ClientHash,
        scan_id: String,
    ) -> Result<MappedID, Error> {
        let row = query("INSERT INTO client_scan_map(client_id, scan_id) VALUES (?, ?)")
            .bind(client.to_string())
            .bind(scan_id)
            .execute(&self.pool)
            .await?;
        let id = row.last_insert_rowid().to_string();
        Ok(id)
    }
    async fn list_mapped_scan_ids(&self, client: &ClientHash) -> Result<Vec<String>, Error> {
        let scan_ids =
            sqlx::query_scalar("SELECT scan_id FROM client_scan_map WHERE client_id = ?")
                .bind(client.to_string())
                .fetch_all(&self.pool)
                .await?;
        Ok(scan_ids)
    }
    async fn get_mapped_id(&self, client: &ClientHash, scan_id: &str) -> Result<MappedID, Error> {
        let scan_ids = sqlx::query_scalar(
            "SELECT id FROM client_scan_map WHERE client_id = ? AND scan_id = ?",
        )
        .bind(client.to_string())
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(scan_ids)
    }
    //TODO: remove when inmemory and file storage are deleted
    async fn remove_mapped_id(&self, id: &str) -> Result<(), Error> {
        self.remove_scan(id).await
    }
}

impl<E> FromConfigAndFeeds for Storage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static + Default,
{
    // Tell me why, why aren't you async? Why keeping it sync? Who
    async fn from_config_and_feeds(
        config: &Config,
        // TODO: why not config?
        feeds: Vec<FeedHash>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::{
            Sqlite,
            pool::PoolOptions,
            sqlite::{SqliteConnectOptions, SqliteJournalMode},
        };
        // TODO: calculate max_connections or change configuration
        let max_connections = 4;
        // TODO: make busy_timeout a configuration option
        let busy_timeout = Duration::from_secs(2);

        let options = SqliteConnectOptions::from_str(&from_config_to_sqlite_address(config))?
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(busy_timeout)
            .create_if_missing(true);
        let pool = PoolOptions::<Sqlite>::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        for hash in feeds.iter() {
            Self::insert_feed_hash(pool.clone(), hash).await?;
        }

        Ok(sqlite::Storage {
            crypter: Arc::new(E::default()),
            pool,
            script_storage: Arc::new(scannerlib::storage::inmemory::InMemoryStorage::default()),
        })
    }
}

impl<E> Storage<E>
where
    E: Send + Sync + 'static,
{
    // TODO test if QueryBuilder and just push values would be faster?
    async fn store_plugin(
        pool: sqlx::Pool<sqlx::Sqlite>,
        feed_hash: &FeedHash,
        plugin: Nvt,
    ) -> Result<(), Error> {
        let mut conn = pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let json = serde_json::to_vec(&plugin)?;
        query(r#" INSERT INTO plugins ( oid, json_blob, feed_type) VALUES (?, ?, ?)"#)
            .bind(&plugin.oid)
            .bind(&json)
            .bind(feed_hash.typus.as_ref())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn synchronize_json<F>(
        pool: sqlx::Pool<sqlx::Sqlite>,
        hash: &FeedHash,
        f: F,
    ) -> Result<(), Error>
    where
        F: Fn(std::sync::mpsc::Sender<Nvt>) -> Result<(), Error> + Send + 'static,
    {
        let (tx_async, mut rx_async) = tokio::sync::mpsc::channel::<Nvt>(1);

        let (tx_blocking, rx_blocking) = std::sync::mpsc::channel::<Nvt>();

        // background task to bridge between sync and async.
        // If we don't do that we may block the runtime
        let forwarder = tokio::spawn(async move {
            for item in rx_blocking {
                if tx_async.send(item).await.is_err() {
                    break;
                }
            }
        });

        let serde_handler = tokio::task::spawn_blocking(move || f(tx_blocking));

        while let Some(plugin) = rx_async.recv().await {
            Self::store_plugin(pool.clone(), hash, plugin).await?;
        }

        serde_handler
            .await
            .expect("tokio::task::spawn_blocking to be executed to run")?;
        forwarder
            .await
            .expect("tokio::task::spawn_blocking to be executed to run");

        Ok(())
    }

    async fn synchronize_vts(pool: sqlx::Pool<sqlx::Sqlite>, hash: FeedHash) -> Result<(), Error> {
        let mut path = hash.path.clone();
        // if a feedpath is provided we expect a vt-metadata.json
        // if it is not a dir we assume it is the json file and continue
        if path.is_dir() {
            // TODO: validate hash_sum if required? For that we would need load the sha256sums, find
            // vt-metadata.json and then verify the sha256sum
            path.push("vt-metadata.json");
            if !path.is_file() {
                return Err(Error::NotFound);
            }
        }
        Self::synchronize_json(pool, &hash, move |sender| {
            let file = std::fs::File::open(&path).map_err(|x| {
                tracing::warn!(?path, error=%x, "Unable to open");
                Error::NotFound
            })?;
            let reader = BufReader::new(file);
            for element in
                super::json_stream::iter_json_array::<Nvt, _>(reader).filter_map(|x| x.ok())
            {
                if sender.send(element).is_err() {
                    break;
                }
            }

            Ok(())
        })
        .await
    }

    async fn synchronize_advisories(
        pool: sqlx::Pool<sqlx::Sqlite>,
        hash: FeedHash,
    ) -> Result<(), Error> {
        let path = hash.path.clone();
        Self::synchronize_json(pool, &hash, move |sender| {
            let loader = FSPluginLoader::new(&path);
            let advisories_files = HashsumAdvisoryLoader::new(loader.clone())?;
            for filename in advisories_files.get_advisories()?.iter() {
                let advisories = advisories_files.load_advisory(filename)?;
                for adv in advisories.advisories {
                    let data: Nvt = VulnerabilityData {
                        adv,
                        family: advisories.family.clone(),
                        filename: filename.to_owned(),
                    }
                    .into();

                    if sender.send(data).is_err() {
                        break;
                    }
                }
            }
            Ok(())
        })
        .await
    }

    async fn insert_feed_hash(
        pool: sqlx::Pool<sqlx::Sqlite>,
        hash: &FeedHash,
    ) -> Result<(), Error> {
        query("INSERT OR REPLACE INTO feed (hash, path, type) VALUES (?, ?, ?)")
            .bind(&hash.hash)
            .bind(hash.path.to_str().unwrap_or_default())
            .bind(hash.typus.as_ref())
            .execute(&pool)
            .await?;
        Ok(())
    }

    pub async fn load_tags(
        &self,
    ) -> Result<HashMap<String, BTreeMap<TagKey, TagValue>>, sqlx::Error> {
        let mut map: HashMap<String, BTreeMap<TagKey, TagValue>> = HashMap::new();
        let mut rows = sqlx::query("SELECT oid, key, value FROM tags").fetch(&self.pool);

        while let Some(row) = rows.try_next().await? {
            let oid: String = row.get("oid");
            let key: TagKey = match TagKey::from_str(row.get("key")) {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error=%e, "Unable to parse tagkey");
                    continue;
                }
            };
            let value = match TagValue::parse(key, row.get::<String, _>("value")) {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error=%e, key=key.as_ref(), "Unable to parse tagvalue");
                    continue;
                }
            };

            map.entry(oid).or_default().insert(key, value);
        }

        Ok(map)
    }

    pub async fn load_single_key_table(
        &self,
        table: &str,
        column: &str,
    ) -> Result<HashMap<String, Vec<String>>, sqlx::Error> {
        let query = format!("SELECT oid, {column} FROM {table}");
        let mut rows = sqlx::query(&query).fetch(&self.pool);

        let mut map: HashMap<String, Vec<String>> = HashMap::new();

        while let Some(row) = rows.try_next().await? {
            let oid: String = row.get("oid");
            let value: String = row.get(column);
            map.entry(oid).or_default().push(value);
        }

        Ok(map)
    }

    pub async fn load_references(&self) -> Result<HashMap<String, Vec<NvtRef>>, sqlx::Error> {
        let mut map: HashMap<String, Vec<NvtRef>> = HashMap::new();
        let mut rows =
            sqlx::query("SELECT oid, class, ref_id FROM plugin_references").fetch(&self.pool);

        while let Some(row) = rows.try_next().await? {
            let oid: String = row.get("oid");
            let class: String = row.get("class");
            let id: String = row.get("ref_id");

            map.entry(oid).or_default().push(NvtRef { class, id });
        }

        Ok(map)
    }

    pub async fn load_preferences(
        &self,
    ) -> Result<HashMap<String, Vec<NvtPreference>>, sqlx::Error> {
        let mut map: HashMap<String, Vec<NvtPreference>> = HashMap::new();
        let mut rows =
            sqlx::query("SELECT oid, id, class, name, default_value FROM plugin_preferences")
                .fetch(&self.pool);

        while let Some(row) = rows.try_next().await? {
            let oid: String = row.get("oid");
            let id: Option<i32> = row.get("id");
            let class = match PreferenceType::from_str(row.get("class")) {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error=%e, "Unable to preference class");
                    continue;
                }
            };
            let name: String = row.get("name");
            let default_value: String = row.get("default_value");

            map.entry(oid).or_default().push(NvtPreference {
                id,
                class,
                name,
                default: default_value,
            });
        }

        Ok(map)
    }
}

#[async_trait]
impl<E> NVTStorer for Storage<E>
where
    E: Send + Sync + 'static,
{
    // signature check is done previously, so we don't need to do that here
    async fn synchronize_feeds(&self, hash: Vec<FeedHash>) -> Result<(), Error> {
        let hashsums = hash
            .into_iter()
            .filter(|x| !matches!(x.typus, FeedType::Products));
        tracing::debug!("synchronize_feeds");
        let mut tasks = futures::stream::FuturesUnordered::new();
        for hash in hashsums {
            let pool = self.pool.clone();
            Self::insert_feed_hash(pool.clone(), &hash).await?;
            match &hash.typus {
                FeedType::Advisories => tasks.push(tokio::task::spawn(async move {
                    Self::synchronize_advisories(pool, hash).await
                })),
                FeedType::NASL => tasks.push(tokio::task::spawn(async move {
                    Self::synchronize_vts(pool, hash).await
                })),
                FeedType::Products => { // ignore 
                }
            }
        }
        while let Some(Ok(result)) = tasks.next().await {
            result?
        }

        tracing::info!("synchronize_feeds end");

        Ok(())
    }

    async fn vts<'a>(&self) -> Result<Vec<Nvt>, Error> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let mut plugins = query("SELECT json_blob FROM plugins ORDER BY oid").fetch(&mut *tx);

        let mut nvts = Vec::new();
        while let Some(row) = plugins.try_next().await? {
            nvts.push(serde_json::from_slice(row.get("json_blob"))?);
        }

        Ok(nvts)
    }

    async fn vt_by_oid(&self, oid: &str) -> Result<Option<Nvt>, Error> {
        let plugin: Option<Result<Nvt, Error>> =
            query_scalar("SELECT json_blob FROM plugins WHERE oid = ?")
                .bind(oid)
                .fetch_optional(&self.pool)
                .await?
                .map(|x: String| serde_json::from_str(&x).map_err(|x| x.into()));
        match plugin {
            None => Ok(None),
            Some(Ok(x)) => Ok(Some(x)),
            Some(Err(x)) => Err(x),
        }
    }

    async fn oids(&self) -> Result<Vec<String>, Error> {
        query_scalar("SELECT oid FROM plugins ORDER BY oid")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.into())
    }

    async fn feed_hash(&self) -> Vec<FeedHash> {
        let rows = query("SELECT hash, path, type FROM feed")
            .fetch_all(&self.pool)
            .await
            .unwrap();
        rows.iter()
            .map(|row| FeedHash {
                hash: row.get("hash"),
                path: row.get::<&str, _>("path").into(),
                typus: row.get::<&str, _>("type").into(),
            })
            .collect()
    }

    async fn current_feed_version(&self) -> Result<String, Error> {
        query_scalar("SELECT hash FROM feed WHERE type = 'nasl'")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| e.into())
    }
}

impl<C> super::ResultHandler for Storage<C>
where
    C: crate::crypt::Crypt + Send + Sync + 'static,
{
    //TODO: get rid of that concept of underlying_storage in favor of seperating script_storage and
    //service_storage. The script storage is actually just needed in openvasd mode while NVT feed
    //update must be handled via json when available.
    fn underlying_storage(&self) -> &Arc<InMemoryStorage> {
        &self.script_storage
    }

    fn handle_result<E>(&self, key: &str, result: models::Result) -> Result<(), E>
    where
        E: From<StorageError>,
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use crypt::{ChaCha20Crypt, Crypt};
    use models::{AliveTestMethods, PrivilegeInformation, Scan, ScanPreference, Service};
    use openssl::conf;
    use scannerlib::{
        models::{Credential, CredentialType},
        scanner::preferences::preference::ScanPrefs,
        storage::{
            self,
            items::nvt::{ACT, NvtPreference, NvtRef, PreferenceType, TagKey, TagValue},
        },
    };

    use crate::config::StorageType;

    use super::*;

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

    fn generate_scan_prefs() -> ScanPrefs {
        ScanPrefs(vec![ScanPreference {
            id: "moep".into(),
            value: "narf".into(),
        }])
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

    fn generate_scan() -> Vec<models::Scan> {
        generate_targets()
            .into_iter()
            .map(|target| models::Scan {
                scan_id: uuid::Uuid::new_v4().to_string(),
                target,
                scan_preferences: generate_scan_prefs(),
                vts: generate_vts(),
            })
            .collect()
    }

    async fn insert_scans() -> (super::Storage<ChaCha20Crypt>, Vec<Scan>, Vec<String>) {
        let config = Config::default();
        let feeds = Default::default();
        let storage = super::Storage::<ChaCha20Crypt>::from_config_and_feeds(&config, feeds)
            .await
            .unwrap();

        let scans = generate_scan();
        let mut mapped_ids = Vec::with_capacity(scans.len());
        for (idx, scan) in scans.iter().enumerate() {
            let client = if idx % 2 == 0 {
                "client_mapping0"
            } else {
                "client_mapping1"
            };

            mapped_ids.push(
                storage
                    .generate_mapped_id(client.into(), scan.scan_id.clone())
                    .await
                    .unwrap(),
            );
            storage.insert_scan(scan.clone()).await.unwrap();
        }
        (storage, scans, mapped_ids)
    }

    #[tokio::test]
    async fn get_plugins() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn generate_plugins() -> Vec<Nvt> {
        let random_name = || uuid::Uuid::new_v4().to_string();
        let tag_variants = || {
            BTreeMap::from([
                (TagKey::Affected, TagValue::String("affected".into())),
                (TagKey::CreationDate, "2012-09-23 02:15:34 -0400".into()),
                (TagKey::CvssBase, TagValue::Null),
                (
                    TagKey::CvssBaseVector,
                    TagValue::Array(vec![TagValue::String("use me".into())]),
                ),
                (TagKey::Deprecated, TagValue::Boolean(true)),
                (TagKey::Impact, TagValue::Boolean(false)),
                (TagKey::Insight, TagValue::Boolean(true)),
                (TagKey::LastModification, "2012-09-23 02:15:34 -0400".into()),
                (TagKey::Qod, TagValue::Number(42)),
                (TagKey::QodType, "exploit".into()),
                (TagKey::SeverityDate, "2012-09-23 02:15:34 -0400".into()),
                (TagKey::SeverityOrigin, TagValue::Null),
                (TagKey::SeverityVector, TagValue::Null),
                (TagKey::Solution, TagValue::Null),
                (TagKey::SolutionMethod, TagValue::Null),
                (TagKey::SolutionType, "WillNotFix".into()),
                (TagKey::Summary, TagValue::Null),
                (TagKey::Vuldetect, TagValue::Null),
            ])
        };
        let preference_variants = || {
            vec![
                NvtPreference {
                    id: Some(0),
                    class: PreferenceType::CheckBox,
                    name: random_name(),
                    default: random_name(),
                },
                NvtPreference {
                    id: Some(1),
                    class: PreferenceType::Entry,
                    name: random_name(),
                    default: random_name(),
                },
                NvtPreference {
                    id: Some(2),
                    class: PreferenceType::File,
                    name: random_name(),
                    default: random_name(),
                },
                NvtPreference {
                    id: Some(3),
                    class: PreferenceType::Password,
                    name: random_name(),
                    default: random_name(),
                },
                NvtPreference {
                    id: Some(4),
                    class: PreferenceType::Radio,
                    name: random_name(),
                    default: random_name(),
                },
                NvtPreference {
                    id: Some(5),
                    class: PreferenceType::SshLogin,
                    name: random_name(),
                    default: random_name(),
                },
                NvtPreference {
                    id: Some(6),
                    class: PreferenceType::Integer,
                    name: random_name(),
                    default: random_name(),
                },
            ]
        };

        vec![
            Nvt {
                oid: random_name(),
                name: random_name(),
                filename: random_name(),
                tag: tag_variants(),
                dependencies: vec![random_name()],
                required_keys: vec![random_name()],
                mandatory_keys: vec![random_name()],
                excluded_keys: vec![random_name()],
                required_ports: vec![random_name()],
                required_udp_ports: vec![random_name()],
                references: vec![NvtRef {
                    class: random_name(),
                    id: random_name(),
                }],
                preferences: preference_variants(),
                category: ACT::Init,
                family: random_name(),
            },
            Nvt {
                oid: random_name(),
                category: ACT::Scanner,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::Settings,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::GatherInfo,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::Attack,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::MixedAttack,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::DestructiveAttack,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::Denial,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::KillHost,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::Flood,
                ..Default::default()
            },
            Nvt {
                oid: random_name(),
                category: ACT::End,
                ..Default::default()
            },
        ]
    }

    #[tokio::test]
    async fn check_oids() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::default();
        let feed = FeedHash {
            hash: "moep".into(),
            path: "doesn't matter".into(),
            typus: FeedType::NASL,
        };
        let storage = super::Storage::<ChaCha20Crypt>::from_config_and_feeds(&config, vec![])
            .await
            .unwrap();
        let mut plugins = generate_plugins();
        super::Storage::<ChaCha20Crypt>::insert_feed_hash(storage.pool.clone(), &feed).await?;
        for p in plugins.clone() {
            super::Storage::<ChaCha20Crypt>::store_plugin(storage.pool.clone(), &feed, p).await?;
        }
        // in the case that examples are changed, I don't want to change this test each time hence
        // we just verify if we got oids.
        let oids = storage.oids().await?;

        assert_eq!(
            oids,
            plugins
                .iter()
                .map(|x| x.oid.clone())
                .sorted_by(|a, b| a.cmp(b))
                .collect::<Vec<String>>()
        );
        let mut db_plugins = storage.vts().await?;
        db_plugins.sort_by(|a, b| a.oid.cmp(&b.oid));
        plugins.sort_by(|a, b| a.oid.cmp(&b.oid));
        assert_eq!(db_plugins.len(), plugins.len());
        //assert_eq!(plugins, db_plugins);
        plugins.iter().zip(db_plugins.iter()).for_each(|(p, dbp)| {
            assert_eq!(p.oid, dbp.oid);
            assert_eq!(p.name, dbp.name);
            assert_eq!(p.filename, dbp.filename);
            assert_eq!(p.category, dbp.category);
            assert_eq!(p.family, dbp.family);
            assert_eq!(p.tag.len(), dbp.tag.len());
            assert_eq!(p.dependencies.len(), dbp.dependencies.len());
            assert_eq!(p.required_keys.len(), dbp.required_keys.len());
            assert_eq!(p.mandatory_keys.len(), dbp.mandatory_keys.len());
            assert_eq!(p.excluded_keys.len(), dbp.excluded_keys.len());
            assert_eq!(p.required_ports.len(), dbp.required_ports.len());
            assert_eq!(p.required_udp_ports.len(), dbp.required_udp_ports.len());
            assert_eq!(p.references.len(), dbp.references.len());
            assert_eq!(p.preferences.len(), dbp.preferences.len());
        });

        Ok(())
    }

    #[tokio::test]
    async fn plugin_shadow_copy() -> Result<(), Box<dyn std::error::Error>> {
        let nasl = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/nasl").into();
        let notus = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/feed/notus/advisories"
        )
        .into();
        let config = Config::default();
        let feeds = vec![
            FeedHash {
                hash: "moep".into(),
                path: nasl,
                typus: FeedType::NASL,
            },
            FeedHash {
                hash: "moep2".into(),
                path: notus,
                typus: FeedType::Advisories,
            },
        ];
        let storage =
            super::Storage::<ChaCha20Crypt>::from_config_and_feeds(&config, feeds.clone())
                .await
                .unwrap();
        storage.synchronize_feeds(feeds).await?;
        // in the case that examples are changed, I don't want to change this test each time hence
        // we just verify if we got oids.
        let oids = storage.oids().await?;
        assert!(!oids.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn client_mapping_not_available() {
        let config = Config::default();
        let feeds = Default::default();
        let storage = super::Storage::<ChaCha20Crypt>::from_config_and_feeds(&config, feeds)
            .await
            .unwrap();
        let result = storage.get_mapped_id(&"0".into(), "0").await;
        assert!(matches!(result, Err(super::Error::NotFound)));
    }

    #[tokio::test]
    async fn update_status() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, _, mapped_ids) = insert_scans().await;
        let first_id = mapped_ids.first().unwrap();
        let mut status = models::Status {
            start_time: Some(23),
            end_time: Some(42),
            status: models::Phase::Running,
            host_info: Some(models::HostInfo {
                all: 42,
                excluded: 2,
                dead: 3,
                alive: 30,
                queued: 7,
                finished: 35,
                scanning: None,
                remaining_vts_per_host: Default::default(),
            }),
        };
        let last_id = mapped_ids.last().unwrap();
        storage.update_status(first_id, status.clone()).await?;
        let (_, actual_status) = storage.get_scan(first_id).await?;
        assert_eq!(actual_status, status);
        status.start_time = None;
        status.end_time = None;
        status.host_info = None;
        storage.update_status(last_id, status.clone()).await?;

        let (_, actual_status) = storage.get_scan(last_id).await?;
        status.host_info = Some(models::HostInfo::default());
        assert_eq!(actual_status, status);

        Ok(())
    }

    #[tokio::test]
    async fn client_mapping() {
        let config = Config::default();
        let feeds = Default::default();
        let storage = super::Storage::<ChaCha20Crypt>::from_config_and_feeds(&config, feeds)
            .await
            .unwrap();
        let scans = generate_scan();
        let mut mapped_ids = Vec::with_capacity(scans.len());
        for (idx, scan) in scans.into_iter().enumerate() {
            let client = if idx % 2 == 0 {
                "client_mapping0"
            } else {
                "client_mapping1"
            };

            mapped_ids.push(
                storage
                    .generate_mapped_id(client.into(), scan.scan_id.clone())
                    .await
                    .unwrap(),
            );
            storage.insert_scan(scan).await.unwrap();
        }
        assert_eq!(
            storage
                .list_mapped_scan_ids(&"client_mapping0".into())
                .await
                .unwrap()
                .len(),
            mapped_ids.len() / 2
        );
        assert_eq!(
            storage
                .list_mapped_scan_ids(&"client_mapping1".into())
                .await
                .unwrap()
                .len(),
            mapped_ids.len() / 2
        );

        for id in mapped_ids {
            storage.remove_scan(&id).await.unwrap();
        }
    }

    #[tokio::test]
    async fn store_results() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, _, mapped_ids) = insert_scans().await;
        let first_id = mapped_ids.first().unwrap();
        let generated_results = vec![
            models::Result {
                id: 0,
                r_type: models::ResultType::Alarm,
                ip_address: None,
                hostname: None,
                oid: None,
                port: None,
                protocol: None,
                message: None,
                detail: None,
            },
            models::Result {
                id: 1,
                r_type: models::ResultType::Log,
                ip_address: Some("127.0.0.1".to_string()),
                hostname: Some("localhost".to_string()),
                oid: Some("1".to_string()),
                port: Some(22),
                protocol: Some(models::Protocol::UDP),
                message: Some("hooary".to_string()),
                detail: Some(models::Detail {
                    name: "detail_name".to_string(),
                    value: "detail_value".to_string(),
                    source: models::Source {
                        s_type: "dunno".to_string(),
                        name: "something".to_string(),
                        description: "found something in don't know".to_string(),
                    },
                }),
            },
        ];
        let status = models::Status {
            host_info: Some(models::HostInfo {
                all: 12,
                excluded: 0,
                dead: 1,
                alive: 10,
                queued: 1,
                finished: 11,
                ..Default::default()
            }),
            ..Default::default()
        };
        let results = ScanResults {
            id: first_id.to_string(),
            status,
            results: generated_results.clone(),
        };

        storage
            .append_fetched_result(ScanResultKind::StatusAddition, results)
            .await?;
        let results = storage.get_results(first_id, None, None).await?;
        assert_eq!(results.count(), generated_results.len());

        Ok(())
    }

    #[tokio::test]
    async fn store_scan() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, scans, mapped_ids) = insert_scans().await;
        assert_eq!(mapped_ids.len(), scans.len());
        for (scan, id) in scans.iter().zip(mapped_ids.iter()) {
            let (actual_scan, _) = storage.get_scan(id).await?;
            assert_eq!(scan.scan_id, actual_scan.scan_id);
        }

        for id in mapped_ids {
            storage.remove_scan(&id).await.unwrap();
        }
        assert_eq!(
            storage
                .list_mapped_scan_ids(&"scan".into())
                .await
                .unwrap()
                .len(),
            0
        );
        Ok(())
    }
}
