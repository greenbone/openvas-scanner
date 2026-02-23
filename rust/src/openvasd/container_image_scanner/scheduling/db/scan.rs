use std::str::FromStr;

use futures::StreamExt;
use greenbone_scanner_framework::InternalIdentifier;
use scannerlib::models::{self, Scan};

use sqlx::{Acquire, QueryBuilder, Row, SqlitePool, query, sqlite::SqliteRow};

use crate::{
    container_image_scanner::image::{Image, ImageState},
    database::dao::{DAOError, DAOPromiseRef, DAOStreamer, Delete, Fetch, Insert, StreamFetch},
};

#[derive(Debug, Clone)]
pub struct SqliteScan<'o, C, T> {
    client_id: C,
    scan: T,
    pool: &'o SqlitePool,
}

impl<'o, C, T> SqliteScan<'o, C, T> {
    pub fn new(client_id: C, scan: T, pool: &'o SqlitePool) -> SqliteScan<'o, C, T> {
        SqliteScan {
            client_id,
            scan,
            pool,
        }
    }
}

impl<'o> Insert for SqliteScan<'o, &str, &Scan> {
    fn insert<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let scan = &self.scan;
            let mut conn = self.pool.acquire().await?;
            let mut tx = conn.begin().await?;
            let row = query(
                r#"
            INSERT INTO client_scan_map(scan_id, client_id) VALUES (?, ?)
            "#,
            )
            .bind(&scan.scan_id)
            .bind(self.client_id)
            .execute(&mut *tx)
            .await?;
            let id = row.last_insert_rowid();
            let _ = query("INSERT INTO scans(id) VALUES (?)")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tracing::debug!(internal_id = id, "creating scan");
            if !scan.target.hosts.is_empty() {
                let mut builder = QueryBuilder::new("INSERT INTO registry (id, host) ");
                builder.push_values(&scan.target.hosts, |mut b, registry| {
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
                builder.push_values(&scan.scan_preferences, |mut b, pref| {
                    b.push_bind(id).push_bind(&pref.id).push_bind(&pref.value);
                });
                let query = builder.build();
                query.execute(&mut *tx).await?;
            }
            Image::insert(
                &mut tx,
                id,
                ImageState::Excluded,
                scan.target.excluded_hosts.clone(),
            )
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }
}

impl<'o> Fetch<Option<InternalIdentifier>> for SqliteScan<'o, &str, &str> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, Option<InternalIdentifier>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let x = query("SELECT id FROM client_scan_map WHERE client_id = ? AND scan_id = ?")
                .bind(self.client_id)
                .bind(self.scan)
                .fetch_optional(self.pool)
                .await?;
            Ok(x.map(|r| r.get::<i64, _>("id")).map(|x| x.to_string()))
        })
    }
}

impl<'o> StreamFetch<String> for SqliteScan<'o, String, ()> {
    fn stream_fetch(self) -> DAOStreamer<String> {
        let result = query(
            r#"
                SELECT scan_id FROM client_scan_map WHERE client_id = ?
            "#,
        )
        .bind(self.client_id)
        .fetch(self.pool)
        .map(|x| {
            x.map(|x| x.get::<String, _>("scan_id"))
                .map_err(DAOError::from)
        });
        Box::pin(result)
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

impl<'o> StreamFetch<models::Result>
    for SqliteScan<'o, (), (String, Option<usize>, Option<usize>)>
{
    fn stream_fetch(self) -> DAOStreamer<models::Result> {
        let (id, from, to) = self.scan;
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

        let result = query
            .fetch(self.pool)
            .map(|x| x.map(row_to_result).map_err(DAOError::from));
        Box::pin(result)
    }
}

impl<'o> Fetch<models::Scan> for SqliteScan<'o, (), String> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Scan>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let mut conn = self.pool.acquire().await?;
            let id = &self.scan;
            let hosts: Vec<(String,)> = sqlx::query_as("SELECT host FROM registry WHERE id = ?")
                .bind(id)
                .fetch_all(&mut *conn)
                .await?;
            let creds: Vec<(String, String)> =
                sqlx::query_as("SELECT username, password FROM credentials WHERE id = ?")
                    .bind(id)
                    .fetch_all(&mut *conn)
                    .await?;

            let preferences: Vec<(String, String)> =
                sqlx::query_as("SELECT key, value FROM preferences WHERE id = ?")
                    .bind(id)
                    .fetch_all(&mut *conn)
                    .await?;
            let scan_id = sqlx::query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
                .bind(id)
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
        })
    }
}

impl<'o> Fetch<models::Result> for SqliteScan<'o, (), (String, usize)> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Result>
    where
        'a: 'b,
    {
        {
            const SQL: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id = ?
"#;

            Box::pin(async move {
                let (id, result_id) = &self.scan;
                query(SQL)
                    .bind(id)
                    .bind(*result_id as i64)
                    .fetch_one(self.pool)
                    .await
                    .map(row_to_result)
                    .map_err(DAOError::from)
            })
        }
    }
}

fn row_to_status(row: SqliteRow) -> models::Status {
    let status = models::Phase::from_str(&row.get::<String, _>("status"))
        .expect("expact status to be a valid phase");
    let host_info = models::HostInfo {
        all: row.get("host_all"),
        alive: row.get("host_alive"),
        dead: row.get("host_dead"),
        queued: row.get("host_queued"),
        finished: row.get("host_finished"),
        excluded: row.get("host_excluded"),
        scanning: None,
        remaining_vts_per_host: Default::default(),
    };

    models::Status {
        start_time: row.get::<Option<u64>, _>("start_time"),
        end_time: row.get::<Option<u64>, _>("end_time"),
        status,
        host_info: Some(host_info),
    }
}

impl<'o> Fetch<models::Status> for SqliteScan<'o, (), String> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Status>
    where
        'a: 'b,
    {
        const SQL: &str = r#"SELECT start_time, end_time, status, host_all, host_alive, host_dead, host_queued, host_finished, host_excluded
                FROM scans 
                WHERE id = ? "#;
        Box::pin(async move {
            query(SQL)
                .bind(&self.scan)
                .fetch_one(self.pool)
                .await
                .map(row_to_status)
                .map_err(DAOError::from)
        })
    }
}

impl<'o> Fetch<models::Phase> for SqliteScan<'o, (), String> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Phase>
    where
        'a: 'b,
    {
        Box::pin(async move {
            const STATUS_SQL: &str = "SELECT status FROM scans WHERE id = ?";
            match query(STATUS_SQL)
                .bind(&self.scan)
                .fetch_one(self.pool)
                .await
            {
                Ok(row) => match models::Phase::from_str(&row.get::<String, _>("status")) {
                    Ok(x) => Ok(x),
                    // should not happen unless data is corrupt
                    Err(_) => Err(DAOError::Corrupt),
                },
                Err(e) => Err(e.into()),
            }
        })
    }
}

impl<'o> Delete for SqliteScan<'o, (), String> {
    fn delete<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        const DELETE_SQL: &str = "DELETE FROM client_scan_map WHERE id = ?";
        Box::pin(async move {
            query(DELETE_SQL)
                .bind(&self.scan)
                .execute(self.pool)
                .await
                .map(|_| ())
                .map_err(DAOError::from)
        })
    }
}
