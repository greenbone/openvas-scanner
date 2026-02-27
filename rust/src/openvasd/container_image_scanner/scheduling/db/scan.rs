use std::str::FromStr;

use futures::StreamExt;
use greenbone_scanner_framework::InternalIdentifier;
use scannerlib::{
    SQLITE_LIMIT_VARIABLE_NUMBER,
    models::{self, Action, Scan},
};

use sqlx::{
    Acquire, Database, QueryBuilder, Row, Sqlite, SqlitePool, query, query::Query,
    sqlite::SqliteRow,
};

use crate::{
    container_image_scanner::image::{Image, ImageState, RegistryError},
    database::dao::{
        DAOError, DAOPromiseRef, DAOStreamer, DBViolation, Delete, Execute, Fetch, Insert,
        StreamFetch,
    },
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

impl<'o> Execute<()> for SqliteScan<'o, (), (&'o str, models::Phase)> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (id, phase) = &self.scan;
            match phase {
                models::Phase::Running => set_scan_to_running(self.pool, id).await,
                models::Phase::Failed => set_scan_to_failed(self.pool, id).await,
                phase => {
                    tracing::warn!(%phase, id, "called with phase that should be handled differently.");
                    return Err(DAOError::Corrupt);

                },
            }
            .map_err(DAOError::from)
        })
    }
}

impl<'o> Execute<()> for SqliteScan<'o, (), (&'o str, &'o [Result<Image, RegistryError>])> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            set_scan_images(self.pool, self.scan.0, self.scan.1)
                .await
                .map_err(DAOError::from)
        })
    }
}

async fn set_scan_images(
    pool: &SqlitePool,
    id: &str,
    images: &[Result<Image, RegistryError>],
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    let count = images.len();
    let dead_count = images.iter().filter(|x| x.is_err()).count();
    let success_count = images.iter().filter(|x| x.is_ok()).count();
    query(
        r#"
            UPDATE scans
            SET host_all = ?,
                host_queued = 0,
                host_dead = ?
            WHERE id = ?
            "#,
    )
    .bind(count as i64)
    .bind(dead_count as i64)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if success_count > 0 {
        let mut builder = QueryBuilder::new("INSERT OR IGNORE INTO images (id, image)");
        builder.push_values(images.iter().filter(|x| x.is_ok()), |mut b, image| {
            let oci = match image {
                Ok(x) => x.to_string(),
                Err(_) => unreachable!("images are filtered for ok"),
            };
            b.push_bind(id).push_bind(oci);
        });
        let query = builder.build();
        query.execute(&mut *tx).await?;
    }
    tx.commit().await?;

    Ok(())
}

impl<'o> Execute<()> for SqliteScan<'o, (), models::Phase> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            set_scans_to_finished(self.pool)
                .await
                .map_err(DAOError::from)
        })
    }
}

pub async fn set_scans_to_finished(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let row = sqlx::query(
        r#"
            UPDATE scans
            SET end_time = strftime('%s', 'now'),
                status = CASE
                            WHEN host_dead = 0 THEN 'succeeded'
                            ELSE 'failed'
                        END
            WHERE status = 'running'
              AND host_queued = 0
              AND NOT EXISTS (
                SELECT 1
                FROM images
                WHERE images.id = scans.id
                  AND status = 'pending'
              );
            "#,
    )
    .execute(pool)
    .await?;

    if row.rows_affected() > 0 {
        tracing::debug!(amount = row.rows_affected(), "finished scans");
    }

    Ok(())
}

async fn set_scan_to_running(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    // setting host_queued to 1 to not trigger success, it will be overridden on set_scan_images
    // later.
    query(
        r#"
            UPDATE scans
            SET status = 'running',
                host_queued = 1
            WHERE id = ? AND status = 'requested'
            "#,
    )
    .bind(id)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn set_scan_to_failed(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    query(
        r#"
            UPDATE scans
            SET status = 'failed'
            WHERE id = ?
            "#,
    )
    .bind(id)
    .execute(pool)
    .await
    .map(|_| ())
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
            for image in scan
                .target
                .excluded_hosts
                .chunks(SQLITE_LIMIT_VARIABLE_NUMBER / 2)
            {
                let mut builder =
                    QueryBuilder::new("INSERT OR IGNORE INTO images (id, image, status)");
                builder.push_values(image, |mut b, img| {
                    b.push_bind(id)
                        .push_bind(img)
                        .push_bind(ImageState::Excluded.as_ref());
                });
                let query = builder.build();
                query.execute(&mut *tx).await?;
            }

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
                    Err(_) => Err(DAOError::DBViolation(DBViolation::CheckViolation)),
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

impl<'o> Execute<()> for SqliteScan<'o, (), (String, models::Action)> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (id, action) = &self.scan;
            match action {
                Action::Start => start_scan(self.pool, id).await,
                Action::Stop => stop_scan(self.pool, id).await,
            }
            .map_err(DAOError::from)
        })
    }
}

async fn with_scan_status<'a, F>(
    pool: &SqlitePool,
    id: &str,
    build_queries: F,
) -> Result<(), sqlx::Error>
where
    F: FnOnce(models::Phase) -> Vec<Query<'a, Sqlite, <Sqlite as Database>::Arguments<'a>>>,
{
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;

    let status = sqlx::query("SELECT status FROM scans WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map(|row| {
            models::Phase::from_str(&row.get::<String, _>("status"))
                .expect("status should be a valid phase")
        })?;
    let queries = build_queries(status);
    for q in queries {
        q.execute(&mut *tx).await?;
    }

    tx.commit().await?;
    Ok(())
}
async fn start_scan(pool: &SqlitePool, id: &str) -> Result<(), sqlx::error::Error> {
    fn update_scan_status<'a>(
        id: &'a str,
        status: &'a str,
    ) -> Query<'a, Sqlite, <Sqlite as Database>::Arguments<'a>> {
        query(
            r#"
        UPDATE scans 
        SET  start_time = strftime('%s', 'now'), end_time = NULL, status = ?
        WHERE id = ?
    "#,
        )
        .bind(status)
        .bind(id)
    }

    with_scan_status(pool, id, |status| {
        let mut queries = Vec::new();

        match status {
            models::Phase::Stored => {
                tracing::debug!(id, "changing from stored to requested.");
                queries.push(update_scan_status(id, "requested"));
            }
            models::Phase::Stopped => {
                tracing::debug!(id, "changing from stopped to running.");
                queries.push(
                    query(
                        r#"
                    UPDATE scans
                    SET status = 
                        CASE
                            WHEN host_all = 0 THEN 'requested'
                            WHEN host_queued > 0 THEN 'running'
                            WHEN host_dead = 0 THEN 'succeeded'
                            ELSE 'failed'
                        END
                    WHERE id = ?"#,
                    )
                    .bind(id),
                );
                queries.push(
                    query(
                        r#"
            UPDATE images
            SET status = 'pending'
            WHERE id = ? AND status = 'stopped'"#,
                    )
                    .bind(id),
                );
            }
            phase => {
                tracing::debug!(?phase, id, "ignoring start command");
            }
        }
        queries
    })
    .await
}

async fn stop_scan(pool: &SqlitePool, id: &str) -> Result<(), sqlx::error::Error> {
    fn update_scan_status<'a>(
        id: &'a str,
    ) -> Query<'a, Sqlite, <Sqlite as Database>::Arguments<'a>> {
        query(
            r#"
        UPDATE scans 
        SET  end_time = strftime('%s', 'now'), status = 'stopped'
        WHERE id = ?
    "#,
        )
        .bind(id)
    }
    with_scan_status(pool, id, |status| {
        let mut queries = Vec::new();

        match status {
            models::Phase::Requested | models::Phase::Stored => {
                tracing::debug!(id, "changing from stored to requested.");
                queries.push(update_scan_status(id));
            }
            models::Phase::Running => {
                tracing::debug!(id, "changing from running to stopped.");
                queries.push(update_scan_status(id));
                queries.push(
                    query(
                        r#"
            UPDATE images
            SET status = 'stopped'
            WHERE id = ? AND status = 'pending'"#,
                    )
                    .bind(id),
                );
            }

            phase => {
                tracing::debug!(?phase, id, "ignoring stop command");
            }
        }
        queries
    })
    .await
}
