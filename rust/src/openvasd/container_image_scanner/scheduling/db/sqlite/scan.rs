use std::str::FromStr;

use scannerlib::models::{self, Action, Scan};

use sqlx::{Acquire, Database, Row, Sqlite, SqlitePool, query, query::Query, sqlite::SqliteRow};

use crate::{
    container_image_scanner::image::{Image, ImageState, RegistryError},
    credentials::{decrypt_credentials, encrypt_credentials},
    crypt::Crypt,
    database::{
        dao::{DAOError, DAOPromiseRef, DBViolation, Execute, Fetch},
        sqlite::{insert_client_scan_map, insert_scan_with_auth_data, insert_values_chunked},
    },
};

pub type DBScan<'o, T> = super::DB<'o, T>;

impl<'o> Execute<()> for DBScan<'o, (&'o str, models::Phase)> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (id, phase) = &self.input;
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

impl<'o> Execute<()> for DBScan<'o, (&'o str, &'o [Result<Image, RegistryError>])> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            set_scan_images(self.pool, self.input.0, self.input.1)
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
                host_queued = ?,
                host_dead = ?
            WHERE id = ?
            "#,
    )
    .bind(count as i64)
    .bind(success_count as i64)
    .bind(dead_count as i64)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if success_count > 0 {
        let images = images
            .iter()
            .filter_map(|image| match image {
                Ok(image) => Some(image.to_string()),
                Err(_) => None,
            })
            .collect::<Vec<_>>();
        insert_values_chunked(
            &mut *tx,
            "INSERT OR IGNORE INTO images (id, image)",
            |mut b, image| {
                b.push_bind(id).push_bind(image);
            },
            &images,
            2,
        )
        .await?;
    }
    tx.commit().await?;
    if success_count == 0 || count == 0 {
        set_scan_to_failed(pool, id).await?;
    }

    Ok(())
}

impl<'o> Execute<()> for DBScan<'o, models::Phase> {
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
    // setting host_queued to 1 prevents the scan from being marked as finished before image
    // resolution stored the actual pending image count.
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

impl<'o, C> Fetch<models::Scan> for DBScan<'o, (&'o C, String)>
where
    C: Crypt + Sync,
{
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Scan>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let mut conn = self.pool.acquire().await?;
            let (crypter, id) = &self.input;
            let hosts: Vec<(String,)> = sqlx::query_as("SELECT host FROM registry WHERE id = ?")
                .bind(id)
                .fetch_all(&mut *conn)
                .await?;
            let auth_data: String = sqlx::query_scalar("SELECT auth_data FROM scans WHERE id = ?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await?;
            let credentials = decrypt_credentials(*crypter, &auth_data).await?;

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
                    credentials,
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

impl<'o, C> Execute<()> for DBScan<'o, (&'o C, &'o str, &'o Scan)>
where
    C: Crypt + Sync,
{
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (crypter, client_id, scan) = &self.input;
            let mut conn = self.pool.acquire().await?;
            let mut tx = conn.begin().await?;
            let id = insert_client_scan_map(&mut *tx, client_id, &scan.scan_id).await?;
            let auth_data = encrypt_credentials(*crypter, &scan.target.credentials).await?;
            insert_scan_with_auth_data(&mut *tx, id, &auth_data).await?;
            tracing::debug!(internal_id = id, "creating scan");
            insert_values_chunked(
                &mut *tx,
                "INSERT INTO registry (id, host)",
                |mut b, registry| {
                    b.push_bind(id).push_bind(registry);
                },
                &scan.target.hosts,
                2,
            )
            .await?;
            insert_values_chunked(
                &mut *tx,
                "INSERT INTO preferences (id, key, value)",
                |mut b, pref| {
                    b.push_bind(id).push_bind(&pref.id).push_bind(&pref.value);
                },
                &scan.scan_preferences,
                3,
            )
            .await?;
            insert_values_chunked(
                &mut *tx,
                "INSERT OR IGNORE INTO images (id, image, status)",
                |mut b, img| {
                    b.push_bind(id)
                        .push_bind(img)
                        .push_bind(ImageState::Excluded.as_ref());
                },
                &scan.target.excluded_hosts,
                3,
            )
            .await?;
            if !scan.target.excluded_hosts.is_empty() {
                query(
                    r#"
                UPDATE scans
                SET host_excluded = host_excluded + ?,
                    host_finished = host_finished + ?
                WHERE id = ?
                "#,
                )
                .bind(scan.target.excluded_hosts.len() as i64)
                .bind(scan.target.excluded_hosts.len() as i64)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            }

            tx.commit().await?;
            Ok(())
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

impl<'o> Fetch<models::Status> for DBScan<'o, String> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Status>
    where
        'a: 'b,
    {
        const SQL: &str = r#"SELECT start_time, end_time, status, host_all, host_alive, host_dead, host_queued, host_finished, host_excluded
                FROM scans 
                WHERE id = ? "#;
        Box::pin(async move {
            query(SQL)
                .bind(&self.input)
                .fetch_one(self.pool)
                .await
                .map(row_to_status)
                .map_err(DAOError::from)
        })
    }
}

impl<'o> Fetch<models::Phase> for DBScan<'o, String> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Phase>
    where
        'a: 'b,
    {
        Box::pin(async move {
            const STATUS_SQL: &str = "SELECT status FROM scans WHERE id = ?";
            match query(STATUS_SQL)
                .bind(&self.input)
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

impl<'o> Execute<()> for DBScan<'o, (String, models::Action)> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (id, action) = &self.input;
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
