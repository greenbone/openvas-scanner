// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use futures::{StreamExt, stream};
use scannerlib::models::{self, AliveTestMethods};
use sqlx::{
    Connection, Row, Sqlite, SqliteConnection, SqlitePool, query, query_scalar, sqlite::SqliteRow,
};

use super::Transaction;
use crate::{
    api::InternalIdentifier,
    crypt::{self, Crypt, Encrypted},
    database::{
        dao::{DAOError, DAOHandler, DAOPromiseRef, DAOStreamer, Execute, Fetch, StreamFetch},
        sqlite::{
            DataBase, OpenVASDDB, insert_values_chunked,
            state_change::{self, row_to_models_status},
        },
    },
};

pub enum ScanIdentifier {
    Oid(i64),
    ScanId(String),
    ClientScanId(String, String),
}

impl From<i64> for ScanIdentifier {
    fn from(value: i64) -> Self {
        Self::Oid(value)
    }
}

impl From<String> for ScanIdentifier {
    fn from(value: String) -> Self {
        Self::ScanId(value)
    }
}

impl From<(String, String)> for ScanIdentifier {
    fn from(value: (String, String)) -> Self {
        Self::ClientScanId(value.0, value.1)
    }
}

impl super::SqliteDatabase {
    pub async fn id_to_oid<T>(&self, id: T) -> anyhow::Result<i64>
    where
        T: Into<ScanIdentifier>,
    {
        let query = match id.into() {
            ScanIdentifier::Oid(oid) => return Ok(oid),
            ScanIdentifier::ScanId(scan_id) => {
                sqlx::query_scalar("SELECT id FROM scans WHERE scan_id = ?").bind(scan_id)
            }
            ScanIdentifier::ClientScanId(client_id, scan_id) => {
                sqlx::query_scalar("SELECT id FROM scans WHERE scan_id = ? AND client_id = ?")
                    .bind(scan_id)
                    .bind(client_id)
            }
        };

        query.fetch_one(&self.pool).await.map_err(|e| e.into())
    }

    pub async fn oid_to_id(&self, tx: &mut Transaction<'_>, oid: i64) -> anyhow::Result<String> {
        let scan_id = sqlx::query_scalar("SELECT scan_id from scans WHERE id = ?")
            .bind(oid)
            .fetch_one(&mut **tx)
            .await?;
        Ok(scan_id)
    }

    pub(super) async fn insert_generic_scan(
        &self,
        tx: &mut Transaction<'_>,
        client_id: &str,
        scan: &models::Scan,
    ) -> anyhow::Result<i64> {
        let scan_oid = query("INSERT INTO scans (scan_id, client_id, auth_data) VALUES (?, ?, ?)")
            .bind(&scan.scan_id)
            .bind(client_id)
            .bind(self.encrypt(&scan.target.credentials).await?)
            .execute(&mut **tx)
            .await?
            .last_insert_rowid();

        let mut scan_preferences = scan.scan_preferences.clone();
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

        insert_values_chunked(
            &mut **tx,
            "INSERT INTO preferences (id, key, value)",
            |mut b, pref| {
                b.push_bind(scan_oid)
                    .push_bind(&pref.id)
                    .push_bind(&pref.value);
            },
            &scan_preferences,
            3,
        )
        .await?;

        Ok(scan_oid)
    }

    pub async fn insert_scan(
        &self,
        tx: &mut Transaction<'_>,
        client_id: &str,
        scan: &models::Scan,
    ) -> anyhow::Result<i64> {
        let scan_oid = self.insert_generic_scan(tx, client_id, scan).await?;

        if !scan.vts.is_empty() {
            insert_values_chunked(
                &mut **tx,
                "INSERT OR REPLACE INTO vts (id, vt)",
                |mut b, vt| {
                    b.push_bind(scan_oid).push_bind(&vt.oid);
                },
                &scan.vts,
                2,
            )
            .await?;

            let vt_params = scan
                .vts
                .iter()
                .flat_map(|x| x.parameters.iter().map(move |p| (&x.oid, p.id, &p.value)))
                .collect::<Vec<_>>();

            insert_values_chunked(
                &mut **tx,
                "INSERT INTO vt_parameters (id, vt, param_id, param_value)",
                |mut b, (oid, param_id, param_value)| {
                    b.push_bind(scan_oid)
                        .push_bind(oid)
                        .push_bind(*param_id as i64)
                        .push_bind(param_value);
                },
                &vt_params,
                4,
            )
            .await?;
        }

        insert_values_chunked(
            &mut **tx,
            "INSERT INTO hosts (id, host)",
            |mut b, host| {
                b.push_bind(scan_oid).push_bind(host);
            },
            &scan.target.hosts,
            2,
        )
        .await?;
        insert_values_chunked(
            &mut **tx,
            "INSERT INTO resolved_hosts (id, original_host, resolved_host, kind, scan_status)",
            |mut b, host| {
                //TODO: check host if ip v4, v6, dns or oci ... for now it doesn't matter.

                b.push_bind(scan_oid)
                    .push_bind(host.clone())
                    .push_bind(host)
                    .push_bind("dns")
                    .push_bind("excluded");
            },
            &scan.target.excluded_hosts,
            5,
        )
        .await?;

        let ports = scan
            .target
            .ports
            .iter()
            .map(|x| (x, false))
            .chain(scan.target.alive_test_ports.iter().map(|x| (x, true)))
            .flat_map(|(port, alive)| {
                port.range
                    .iter()
                    .map(move |r| (port.protocol.as_ref(), r, alive))
            })
            .collect::<Vec<_>>();

        insert_values_chunked(
            &mut **tx,
            "INSERT INTO ports (id, protocol, start, end, alive)",
            |mut b, (protocol, range, alive)| {
                b.push_bind(scan_oid)
                    .push_bind(match protocol {
                        None => "udp_tcp",
                        Some(x) => x.as_ref(),
                    })
                    .push_bind(range.start as i64)
                    .push_bind(range.end.map(|x| x as i64))
                    .push_bind(alive);
            },
            &ports,
            5,
        )
        .await?;

        insert_values_chunked(
            &mut **tx,
            "INSERT INTO alive_methods (id, method)",
            |mut b, method| {
                b.push_bind(scan_oid).push_bind(method.as_ref());
            },
            &scan.target.alive_test_methods,
            2,
        )
        .await?;
        Ok(scan_oid)
    }

    pub async fn get_scan(
        &self,
        tx: &mut SqliteConnection,
        id: ScanIdentifier,
    ) -> anyhow::Result<models::Scan> {
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

        let scan_oid = self.id_to_oid(id).await?;
        let scan_row = sqlx::query(
            "SELECT id, scan_id, created_at, start_time, end_time, auth_data FROM scans WHERE id = ?"
            )
            .bind(scan_oid)
            .fetch_one(&mut *tx)
            .await?;
        let scan_oid: i64 = scan_row.get::<i64, _>("id");

        let preferences: Vec<models::ScanPreference> =
            sqlx::query_as("SELECT key, value FROM preferences WHERE id = ?")
                .bind(scan_oid)
                .fetch_all(&mut *tx)
                .await?;

        let ports = query("SELECT protocol, start, end FROM ports WHERE id = ? AND alive = 0")
            .bind(scan_oid)
            .fetch_all(&mut *tx)
            .await?;
        let ports = rows_to_ports(ports);
        let alive_test_ports =
            query("SELECT protocol, start, end FROM ports WHERE id = ? AND alive = 1")
                .bind(scan_oid)
                .fetch_all(&mut *tx)
                .await?;

        let alive_test_ports = rows_to_ports(alive_test_ports);

        let reverse_lookup_unify = preferences
            .iter()
            .any(|x| &x.id == "target_reverse_lookup_unify" && x.value.parse().unwrap_or_default());
        let reverse_lookup_only = preferences
            .iter()
            .any(|x| &x.id == "target_reverse_lookup_only" && x.value.parse().unwrap_or_default());

        let hosts: Vec<String> = query_scalar("SELECT host FROM hosts WHERE id = ?")
            .bind(scan_oid)
            .fetch_all(&mut *tx)
            .await?;

        let oids = query_scalar("SELECT vt FROM vts WHERE id = ?")
            .bind(scan_oid)
            .fetch_all(&mut *tx)
            .await?;

        let mut vts = Vec::with_capacity(oids.len());
        for oid in oids {
            let parameters = sqlx::query_as(
                "SELECT param_id, param_value FROM vt_parameters WHERE id = ? AND vt = ?",
            )
            .bind(scan_oid)
            .bind(&oid)
            .fetch_all(&mut *tx)
            .await?;
            vts.push(models::VT { oid, parameters });
        }

        // TODO: why not keep it as an integer in the database?
        let alive_methods: Vec<String> =
            query_scalar("SELECT method FROM alive_methods WHERE id = ?")
                .bind(scan_oid)
                .fetch_all(&mut *tx)
                .await?;
        let alive_test_methods = alive_methods
            .iter()
            .map(|x| AliveTestMethods::from(x as &str))
            .collect::<Vec<_>>();
        let excluded_hosts = query_scalar("SELECT original_host FROM resolved_hosts WHERE id = ?")
            .bind(scan_oid)
            .fetch_all(&mut *tx)
            .await?;
        let scan_id = scan_row.get::<String, _>("scan_id");
        let auth_data = scan_row.get::<String, _>("auth_data");
        let credentials: Vec<models::Credential> = self.decrypt(&auth_data).await?;
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

    pub async fn change_scan_state(
        &self,
        tx: &mut SqliteConnection,
        id: i64,
        from: &str,
        to: &str,
    ) -> anyhow::Result<bool> {
        let affected = sqlx::query("UPDATE scans SET status = ? WHERE status = ? AND id = ?")
            .bind(to)
            .bind(from)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();

        tracing::debug!(affected, from, to, id, "Scan status change");

        Ok(affected > 0)
    }

    pub async fn change_scan_state_all(
        &self,
        tx: &mut SqliteConnection,
        from: &str,
        to: &str,
    ) -> anyhow::Result<usize> {
        let affected = sqlx::query("UPDATE scans SET status = ? WHERE status = ?")
            .bind(to)
            .bind(from)
            .execute(&mut *tx)
            .await?
            .rows_affected();

        tracing::debug!(affected, from, to, "Scans status change");

        Ok(affected as usize)
    }

    pub async fn get_scans_in_state(
        &self,
        tx: &mut SqliteConnection,
        state: &str,
        limit: Option<i64>,
    ) -> anyhow::Result<Vec<i64>> {
        let scan_ids: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM scans WHERE status = ? LIMIT ?")
                .bind(state)
                .bind(limit.unwrap_or(-1))
                .fetch_all(&mut *tx)
                .await?;

        Ok(scan_ids)
    }

    pub async fn scan_get_status(
        &self,
        tx: &mut SqliteConnection,
        oid: i64,
    ) -> anyhow::Result<models::Status> {
        let status_row = sqlx::query(r#"
            SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status
            FROM scans
            WHERE id = ?
            "#)
            .bind(oid)
            .fetch_one(&mut *tx)
            .await?;

        let host_scanning_rows = sqlx::query_as(
            r#"
                SELECT host_ip, progress
                FROM host_scanning
                WHERE id = ?
                "#,
        )
        .bind(oid)
        .fetch_all(&mut *tx)
        .await?;

        let result = row_to_models_status(status_row, host_scanning_rows);
        Ok(result)
    }

    pub async fn scan_update_status(
        &self,
        tx: &mut SqliteConnection,
        id: i64,
        status: &models::Status,
    ) -> anyhow::Result<()> {
        let host_info = status.host_info.clone().unwrap_or_default();
        sqlx::query(
            r#"
            UPDATE scans SET
                start_time    = COALESCE(?, start_time),
                end_time      = COALESCE(?, end_time),
                host_dead     = COALESCE(NULLIF(?, 0), host_dead),
                host_alive    = COALESCE(NULLIF(?, 0), host_alive),
                host_queued   = ?,
                host_excluded = COALESCE(NULLIF(?, 0), host_excluded),
                host_all      = COALESCE(NULLIF(?, 0), host_all),
                status        = COALESCE(NULLIF(NULLIF(?, 'stored'), 'requested'), status)
            WHERE id = ?
            "#,
        )
        .bind(status.start_time.map(|x| x as i64))
        .bind(status.end_time.map(|x| x as i64))
        .bind(host_info.dead as i64)
        .bind(host_info.alive as i64)
        .bind(host_info.queued as i64)
        .bind(host_info.excluded as i64)
        .bind(host_info.all as i64)
        .bind(status.status.as_ref())
        .bind(id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE from host_scanning WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if let Some(scanning) = host_info.scanning {
            for (h, p) in scanning {
                sqlx::query("INSERT INTO host_scanning (id, host_ip, progress) VALUES (?, ?, ?)")
                    .bind(id)
                    .bind(h.clone())
                    .bind(p)
                    .execute(&mut *tx)
                    .await?;
            }
        };

        Ok(())
    }

    pub async fn count_scans_in_state(
        &self,
        tx: &mut SqliteConnection,
        // tx: &mut Transaction<'_>,
        state: &str,
    ) -> anyhow::Result<usize> {
        Ok(
            sqlx::query_scalar::<_, i64>("SELECT count(id) FROM scans WHERE status = ?")
                .bind(state)
                .fetch_one(tx)
                .await? as usize,
        )
    }
}

pub type ScanDB<'o, T> = OpenVASDDB<'o, T>;

impl From<crypt::ParseError> for DAOError {
    fn from(value: crypt::ParseError) -> Self {
        tracing::warn!(%value, "Unable to handle encryption on credentials.");
        Self::Corrupt
    }
}

impl From<serde_json::Error> for DAOError {
    fn from(value: serde_json::Error) -> Self {
        tracing::warn!(%value, "Invalid json stored.");
        Self::Corrupt
    }
}

impl<'o, C> Execute<String> for ScanDB<'o, (&'o C, &'o str, &models::Scan)>
where
    C: Sync + Crypt,
{
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, String>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (crypter, client, scan) = &self.input;
            scan_insert(self.pool, *crypter, client, scan).await
        })
    }
}

async fn scan_insert<C>(
    pool: &DataBase,
    crypter: &C,
    client: &str,
    scan: &models::Scan,
) -> Result<String, DAOError>
where
    C: Crypt,
{
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;

    let auth_data = {
        let bytes = serde_json::to_vec(&scan.target.credentials)?;
        let bytes = crypter
            .encrypt(bytes)
            .await
            .map_err(|_| DAOError::Corrupt)?;
        bytes.to_string()
    };
    let mapped_id = query("INSERT INTO scans (client_id, scan_id, auth_data) VALUES (?, ?, ?)")
        .bind(client.to_string())
        .bind(&scan.scan_id)
        .bind(auth_data)
        .execute(&mut *tx)
        .await?
        .last_insert_rowid();
    if !scan.vts.is_empty() {
        insert_values_chunked(
            &mut *tx,
            "INSERT OR REPLACE INTO vts (id, vt)",
            |mut b, vt| {
                b.push_bind(mapped_id).push_bind(&vt.oid);
            },
            &scan.vts,
            2,
        )
        .await?;
        let vt_params = scan
            .vts
            .iter()
            .flat_map(|x| x.parameters.iter().map(move |p| (&x.oid, p.id, &p.value)))
            .collect::<Vec<_>>();
        insert_values_chunked(
            &mut *tx,
            "INSERT INTO vt_parameters (id, vt, param_id, param_value)",
            |mut b, (oid, param_id, param_value)| {
                b.push_bind(mapped_id)
                    .push_bind(oid)
                    .push_bind(*param_id as i64)
                    .push_bind(param_value);
            },
            &vt_params,
            4,
        )
        .await?;
    }

    insert_values_chunked(
        &mut *tx,
        "INSERT INTO hosts (id, host)",
        |mut b, host| {
            b.push_bind(mapped_id).push_bind(host);
        },
        &scan.target.hosts,
        2,
    )
    .await?;

    insert_values_chunked(
        &mut *tx,
        "INSERT INTO resolved_hosts (id, original_host, resolved_host, kind, scan_status)",
        |mut b, host| {
            //TODO: check host if ip v4, v6, dns or oci ... for now it doesn't matter.
            b.push_bind(mapped_id)
                .push_bind(host.clone())
                .push_bind(host)
                .push_bind("dns")
                .push_bind("excluded");
        },
        &scan.target.excluded_hosts,
        5,
    )
    .await?;

    let ports = scan
        .target
        .ports
        .iter()
        .flat_map(|port| {
            port.range
                .clone()
                .into_iter()
                .map(move |r| (port.protocol.as_ref(), r))
        })
        .collect::<Vec<_>>();
    insert_values_chunked(
        &mut *tx,
        "INSERT INTO ports (id, protocol, start, end)",
        |mut b, (protocol, range)| {
            b.push_bind(mapped_id)
                .push_bind(match protocol {
                    None => "udp_tcp",
                    Some(x) => x.as_ref(),
                })
                .push_bind(range.start as i64)
                .push_bind(range.end.map(|x| x as i64));
        },
        &ports,
        4,
    )
    .await?;
    let alive_test_ports = scan
        .target
        .alive_test_ports
        .iter()
        .flat_map(|port| {
            port.range
                .clone()
                .into_iter()
                .map(move |r| (port.protocol.as_ref(), r))
        })
        .collect::<Vec<_>>();
    insert_values_chunked(
        &mut *tx,
        "INSERT INTO ports (id, protocol, start, end, alive)",
        |mut b, (protocol, range)| {
            b.push_bind(mapped_id)
                .push_bind(match protocol {
                    None => "udp_tcp",
                    Some(x) => x.as_ref(),
                })
                .push_bind(range.start as i64)
                .push_bind(range.end.map(|x| x as i64))
                .push_bind(true);
        },
        &alive_test_ports,
        5,
    )
    .await?;

    insert_values_chunked(
        &mut *tx,
        "INSERT INTO alive_methods (id, method)",
        |mut b, method| {
            b.push_bind(mapped_id).push_bind(method.as_ref());
        },
        &scan.target.alive_test_methods,
        2,
    )
    .await?;

    let mut scan_preferences = scan.scan_preferences.clone();
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

    insert_values_chunked(
        &mut *tx,
        "INSERT INTO preferences (id, key, value)",
        |mut b, pref| {
            b.push_bind(mapped_id)
                .push_bind(&pref.id)
                .push_bind(&pref.value);
        },
        &scan_preferences,
        3,
    )
    .await?;

    tx.commit().await?;
    Ok(scan.scan_id.clone())
}

async fn get_scan<C>(
    tx: &mut sqlx::SqliteConnection,
    crypter: &C,
    id: i64,
) -> Result<models::Scan, DAOError>
where
    C: Sync + Crypt,
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
    let preferences: Vec<models::ScanPreference> =
        sqlx::query_as("SELECT key, value FROM preferences WHERE id = ?")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;

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
        let parameters = sqlx::query_as(
            "SELECT param_id, param_value FROM vt_parameters WHERE id = ? AND vt = ?",
        )
        .bind(id)
        .bind(&oid)
        .fetch_all(&mut *tx)
        .await?;
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
    let scan_id: String = query_scalar("SELECT scan_id FROM scans WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

    let excluded_hosts = query_scalar("SELECT original_host FROM resolved_hosts WHERE id = ?")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;

    let auth_data = scan_row.get::<String, _>("auth_data");
    let encrypted: Encrypted = Encrypted::try_from(auth_data)?;
    let auth_data = crypter
        .decrypt(encrypted)
        .await
        .map_err(|_| DAOError::Corrupt)?;
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

impl<'o, C> Fetch<models::Scan> for ScanDB<'o, (&'o C, i64)>
where
    C: Sync + Crypt,
{
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Scan>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (crypter, id) = &self.input;
            let mut conn = self.pool.acquire().await?;
            let mut tx = conn.begin().await?;
            let result = get_scan(&mut tx, *crypter, *id).await;
            tx.commit().await?;
            result
        })
    }
}

pub(crate) async fn scan_get_status<'a, E>(
    pool: E,
    id: i64,
) -> Result<models::Status, sqlx::error::Error>
where
    E: sqlx::Executor<'a, Database = Sqlite> + Clone,
{
    let scan_row = state_change::status_query(id)
        .fetch_one(pool.clone())
        .await?;
    let scan_rows = state_change::host_scanning_query(id)
        .fetch_all(pool)
        .await?;
    Ok(state_change::row_to_models_status(scan_row, scan_rows))
}

impl<'o> Fetch<models::Status> for ScanDB<'o, i64> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Status>
    where
        'a: 'b,
    {
        Box::pin(async move {
            scan_get_status(self.pool, self.input)
                .await
                .map_err(DAOError::from)
        })
    }
}

impl<'o> Fetch<String> for ScanDB<'o, i64> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, String>
    where
        'a: 'b,
    {
        Box::pin(async move {
            query_scalar("SELECT scan_id FROM scans WHERE id = ?")
                .bind(self.input)
                .fetch_one(self.pool)
                .await
                .map_err(DAOError::from)
        })
    }
}

impl<'o> Fetch<i64> for ScanDB<'o, models::Phase> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, i64>
    where
        'a: 'b,
    {
        Box::pin(async move {
            query_scalar("SELECT count(id) FROM scans WHERE status = ?")
                .bind(self.input.as_ref())
                .fetch_one(self.pool)
                .await
                .map_err(DAOError::from)
        })
    }
}

impl<'o, T> Fetch<Option<InternalIdentifier>> for T
where
    T: DAOHandler<&'o SqlitePool, (&'o str, &'o str)> + Sync,
{
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, Option<InternalIdentifier>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (client_id, scan) = self.input();
            let x = query("SELECT id FROM scans WHERE client_id = ? AND scan_id = ?")
                .bind(client_id)
                .bind(scan)
                .fetch_optional(self.db())
                .await?;
            Ok(x.map(|r| r.get::<i64, _>("id")).map(|x| x.to_string()))
        })
    }
}

impl<'o, T> StreamFetch<String> for T
where
    T: DAOHandler<&'o SqlitePool, String> + Sync,
{
    fn stream_fetch(self) -> DAOStreamer<String> {
        let (db, client_id) = self.inner();
        let pool = db.clone();
        // The code below is a temporary fix for a problem we encountered where a response being
        // read slowly if sqlite was configured to only a single connection at a time would lead to
        // a deadlock.
        // The implementation is not great, since it fetches all entries from the DB and
        // then streams them from memory instead of streaming them from the DB, but it prevents the
        // bug, which occurred due to the async task owning the DB connection.
        // TODO: Fix this implementation by removing all these traits and properly implementing the DB access.
        let result = stream::once(async move {
            match query_scalar::<_, String>(
                r#"
                SELECT scan_id FROM scans WHERE client_id = ?
            "#,
            )
            .bind(client_id)
            .fetch_all(&pool)
            .await
            {
                Ok(scan_ids) => scan_ids.into_iter().map(Ok).collect(),
                Err(error) => vec![Err(DAOError::from(error))],
            }
        })
        .flat_map(stream::iter);
        Box::pin(result)
    }
}

impl<'o, T> Execute<()> for T
where
    T: DAOHandler<&'o SqlitePool, String> + Sync,
{
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        const DELETE_SQL: &str = "DELETE FROM scans WHERE id = ?";
        Box::pin(async move {
            query(DELETE_SQL)
                .bind(self.input())
                .execute(self.db())
                .await
                .map(|_| ())
                .map_err(DAOError::from)
        })
    }
}
