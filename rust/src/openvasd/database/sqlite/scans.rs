use futures::StreamExt;
use greenbone_scanner_framework::InternalIdentifier;
use scannerlib::{
    SQLITE_LIMIT_VARIABLE_NUMBER,
    models::{self, AliveTestMethods},
};
use sqlx::{
    Connection, QueryBuilder, Row, Sqlite, SqlitePool, query, query_scalar, sqlite::SqliteRow,
};

use crate::{
    crypt::{self, Crypt, Encrypted},
    database::{
        dao::{DAOError, DAOHandler, DAOPromiseRef, DAOStreamer, Execute, Fetch, StreamFetch},
        sqlite::{DataBase, OpenVASDDB, state_change},
    },
};

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
        for vts in scan.vts.chunks(SQLITE_LIMIT_VARIABLE_NUMBER / 2) {
            let mut builder = QueryBuilder::new("INSERT OR REPLACE INTO vts (id, vt)");
            builder.push_values(vts, |mut b, vt| {
                b.push_bind(&mapped_id).push_bind(&vt.oid);
            });
            let query = builder.build();
            query.execute(&mut *tx).await?;
        }
        let vt_params = scan
            .vts
            .iter()
            .flat_map(|x| x.parameters.iter().map(move |p| (&x.oid, p.id, &p.value)))
            .collect::<Vec<_>>();
        if !vt_params.is_empty() {
            for vt_params in vt_params.chunks(SQLITE_LIMIT_VARIABLE_NUMBER / 3) {
                let mut builder =
                    QueryBuilder::new("INSERT INTO vt_parameters (id, vt, param_id, param_value)");

                builder.push_values(vt_params, |mut b, (oid, param_id, param_value)| {
                    b.push_bind(&mapped_id)
                        .push_bind(oid)
                        .push_bind(*param_id as i64)
                        .push_bind(param_value);
                });
                let query = builder.build();
                query.execute(&mut *tx).await?;
            }
        }
    }

    if !scan.target.hosts.is_empty() {
        let mut builder = QueryBuilder::new("INSERT INTO hosts (id, host)");
        builder.push_values(&scan.target.hosts, |mut b, host| {
            b.push_bind(&mapped_id).push_bind(host);
        });
        let query = builder.build();
        query.execute(&mut *tx).await?;
    }

    if !scan.target.excluded_hosts.is_empty() {
        let mut builder = QueryBuilder::new(
            "INSERT INTO resolved_hosts (id, original_host, resolved_host, kind, scan_status)",
        );
        builder.push_values(&scan.target.excluded_hosts, |mut b, host| {
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
        for ports in scan.target.ports.chunks(SQLITE_LIMIT_VARIABLE_NUMBER / 4) {
            let mut builder = QueryBuilder::new("INSERT INTO ports (id, protocol, start, end) ");
            builder.push_values(
                ports.iter().flat_map(|port| {
                    port.range
                        .clone()
                        .into_iter()
                        .map(move |r| (port.protocol, r))
                }),
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
    }
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
            query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
                .bind(self.input)
                .fetch_one(self.pool)
                .await
                .map_err(DAOError::from)
        })
    }
}

// match query_scalar("SELECT count(id) FROM scans WHERE status = 'running'")
//     .fetch_one(&self.pool)
//     .await
// {
//     Ok(x) => x,
//     Err(error) => {
//         tracing::warn!(
//             %error,
//             "Unable to count running scans, still preventing start of new scans"
//         );
//         1
//     }
// }
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
            let x = query("SELECT id FROM client_scan_map WHERE client_id = ? AND scan_id = ?")
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
        let result = query(
            r#"
                SELECT scan_id FROM client_scan_map WHERE client_id = ?
            "#,
        )
        .bind(client_id)
        .fetch(db)
        .map(|x| {
            x.map(|x| x.get::<String, _>("scan_id"))
                .map_err(DAOError::from)
        });
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
        const DELETE_SQL: &str = "DELETE FROM client_scan_map WHERE id = ?";
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
