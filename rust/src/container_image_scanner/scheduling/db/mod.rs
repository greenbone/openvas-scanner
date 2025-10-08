use std::{collections::HashMap, str::FromStr, sync::Arc};

use futures::{Stream, StreamExt};
use greenbone_scanner_framework::models::{self};
use sqlx::{
    Acquire, Database, Pool, QueryBuilder, Row, Sqlite, query, query::Query, sqlite::SqliteRow,
};
use tracing::debug;

use crate::container_image_scanner::{
    ExternalError,
    image::{Credential, Image, ImageID, ImageParseError},
};

impl From<SqliteRow> for ImageID {
    fn from(row: SqliteRow) -> Self {
        let id: i64 = row.get("id");
        Self {
            id: id.to_string(),
            image: row.get("image"),
        }
    }
}

pub fn row_to_credential(row: &SqliteRow) -> Option<Credential> {
    let username: Option<String> = row.get("username");
    let password: Option<String> = row.get("password");
    match (username, password) {
        (None, None) => None,
        (None, Some(_)) => None,
        (user, pass) => Some(Credential {
            username: user.unwrap_or_default(),
            password: pass.unwrap_or_default(),
        }),
    }
}

async fn with_scan_status<'a, F>(
    pool: &Pool<Sqlite>,
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

async fn stop_scan(pool: &Pool<Sqlite>, id: &str) -> Result<(), sqlx::error::Error> {
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
                debug!(id, "changing from stored to requested.");
                queries.push(update_scan_status(id));
            }
            models::Phase::Running => {
                debug!(id, "changing from running to stopped.");
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
                debug!(?phase, id, "ignoring stop command");
            }
        }
        queries
    })
    .await
}

async fn start_scan(pool: &Pool<Sqlite>, id: &str) -> Result<(), sqlx::error::Error> {
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
                debug!(id, "changing from stored to requested.");
                queries.push(update_scan_status(id, "requested"));
            }
            models::Phase::Stopped => {
                debug!(id, "changing from stopped to running.");
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
                debug!(?phase, id, "ignoring start command");
            }
        }
        queries
    })
    .await
}

pub async fn on_message(pool: &Pool<Sqlite>, msg: &super::Message) -> Result<(), sqlx::Error> {
    match msg.action {
        models::Action::Start => start_scan(pool, &msg.id).await,
        models::Action::Stop => stop_scan(pool, &msg.id).await,
    }
}

pub async fn store_results(
    pool: Arc<sqlx::Pool<Sqlite>>,
    id: &str,
    results: Vec<models::Result>,
) -> Result<(), sqlx::Error> {
    if results.is_empty() {
        return Ok(());
    }
    let mut conn = pool.as_ref().acquire().await?;
    let mut tx = conn.begin().await?;
    // x.map(|x| x.get::<String, _>("scan_id"))
    let base_id = match query(
        r#"
                SELECT COUNT(*) AS result_count
                FROM results
                WHERE scan_id = ? "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(x) => x.get::<i64, _>("result_count"),
        Err(sqlx::Error::RowNotFound) => 0,
        Err(e) => {
            return Err(e);
        }
    };
    tracing::trace!(id, base_id, "Results.");
    let mut builder = QueryBuilder::new(
        r#"
            INSERT INTO results (
                scan_id,
                id,
                type,
                ip_address,
                hostname,
                oid,
                port,
                protocol,
                message,
                detail_name,
                detail_value,
                source_type,
                source_name,
                source_description
            ) 
            "#,
    );

    builder.push_values(results, |mut b, result| {
        let detail = result.detail.unwrap_or_default();
        b.push_bind(id)
            .push_bind(result.id as i64 + base_id)
            .push_bind(result.r_type.to_string())
            .push_bind(result.ip_address.unwrap_or_default())
            .push_bind(result.hostname.unwrap_or_default())
            .push_bind(result.oid.unwrap_or_default())
            .push_bind(result.port.unwrap_or_default())
            .push_bind(result.protocol.map(|x| x.to_string()).unwrap_or_default())
            .push_bind(result.message.unwrap_or_default())
            .push_bind(detail.name)
            .push_bind(detail.value)
            .push_bind(detail.source.s_type)
            .push_bind(detail.source.name)
            .push_bind(detail.source.description);
    });

    let query = builder.build();
    query.execute(&mut *tx).await?;

    tx.commit().await?;

    Ok(())
}

pub async fn set_scan_to_running_and_add_images(
    pool: &Pool<Sqlite>,
    id: &str,
    images: Vec<Result<Image, Box<dyn std::error::Error + Send + Sync>>>,
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    let success_count = images.iter().filter(|x| x.is_ok()).count();
    if let Err(err) = query(
        r#"
            UPDATE scans
            SET host_all = ?,
                host_dead = ?,
                status = 'running'
            WHERE id = ? AND status = 'requested'
            "#,
    )
    .bind(images.len() as i64)
    .bind(images.iter().filter(|x| x.is_err()).count() as i64)
    .bind(id)
    .execute(&mut *tx)
    .await
    {
        unreachable!("The update should not fail. Unable to recover: {err}");
    };
    if success_count > 0 {
        let mut builder = QueryBuilder::new("INSERT OR IGNORE INTO images (id, image)");
        builder.push_values(images.into_iter().filter_map(|x| x.ok()), |mut b, image| {
            b.push_bind(id).push_bind(image.to_string());
        });
        let query = builder.build();
        if let Err(err) = query.execute(&mut *tx).await {
            tracing::warn!(error=%err, "Unable to insert image, this can happen on duplicated entries.");
            return Err(err);
        };

        tx.commit().await?;
    }
    Ok(())
}

fn set_image_status<'a>(
    ids: &'a ImageID,
    status: &'a str,
) -> Query<'a, Sqlite, <Sqlite as Database>::Arguments<'a>> {
    query(
        r#"
            UPDATE images
            SET status = ?
            WHERE id = ? AND image = ?"#,
    )
    .bind(status)
    .bind(ids.id())
    .bind(ids.image())
}

pub async fn image_failed(pool: &sqlx::Pool<Sqlite>, id: &ImageID) -> Result<(), ExternalError> {
    set_image_status(id, "failed").execute(pool).await?;
    Ok(())
}

pub async fn image_success(pool: &sqlx::Pool<Sqlite>, id: &ImageID) -> Result<(), ExternalError> {
    set_image_status(id, "succeeded").execute(pool).await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ProcessingImage {
    pub id: String,
    pub image: Vec<Result<Image, ImageParseError>>,
    pub credentials: Option<Credential>,
}

pub struct RequestedScans(Vec<ProcessingImage>);

impl From<Vec<ProcessingImage>> for RequestedScans {
    fn from(value: Vec<ProcessingImage>) -> Self {
        Self(value)
    }
}

impl Iterator for RequestedScans {
    type Item = ProcessingImage;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop()
    }
}

impl RequestedScans {
    pub async fn fetch(pool: &Pool<Sqlite>, limit: usize) -> RequestedScans {
        let mut stream = sqlx::query(
            r#"
        WITH running_count AS (
            SELECT COUNT(*) AS running_total
            FROM scans
            WHERE status = 'running'
        ),
        selected_scans AS (
            SELECT id
            FROM scans
            WHERE status = 'requested'
            ORDER BY created_at ASC
            LIMIT (
                SELECT MAX(? - running_total, 0)
                FROM running_count
            )
        )
        SELECT 
            r.id,
            r.host AS registry,
            c.username,
            c.password
        FROM registry r
        JOIN selected_scans s
          ON r.id = s.id
        LEFT JOIN credentials c
          ON r.id = c.id
        "#,
        )
        .bind(limit as i64)
        .fetch(pool);
        type ImageResult = Result<Image, ImageParseError>;

        let mut map: HashMap<i64, (Vec<ImageResult>, Option<Credential>)> = HashMap::new();

        while let Some(row_result) = stream.next().await {
            let row = match row_result {
                Ok(x) => x,
                Err(e) => {
                    unreachable!(
                        "Unreachable: SQL query failed despite static structure. Error: {}",
                        e
                    )
                }
            };

            let registry: String = row.get("registry");
            let image = registry.parse();

            let id: i64 = row.get("id");
            let credential = row_to_credential(&row);

            let entry = map.entry(id).or_insert_with(|| (Vec::new(), credential));

            entry.0.push(image);
        }

        let result = map
            .into_iter()
            .map(|(id, (image, credentials))| ProcessingImage {
                id: id.to_string(),
                image,
                credentials,
            })
            .collect();
        RequestedScans(result)
    }
}

pub async fn set_scans_to_finished(pool: &Pool<Sqlite>) -> Result<(), ExternalError> {
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;

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
    .execute(&mut *tx)
    .await?;
    if row.rows_affected() > 0 {
        tracing::debug!(amount = row.rows_affected(), "finished scans");
    }

    tx.commit().await?;
    Ok(())
}

pub(crate) fn preferences<'a>(
    pool: &'a Pool<Sqlite>,
    id: &'a str,
) -> impl Stream<Item = (String, String)> + 'a {
    query(
        r#"SELECT key, value
                FROM preferences
                WHERE id = ? "#,
    )
    .bind(id)
    .fetch(pool)
    .filter_map(|row| async move {
        let row = row.ok()?;
        let key: String = row.get("key");
        let value: String = row.get("value");
        Some((key, value))
    })
}

#[cfg(test)]
mod tests {
    use sqlx::{SqlitePool, query, query_scalar};

    use crate::container_image_scanner::{MIGRATOR, config::DBLocation};

    #[tokio::test]
    async fn status_failed() {
        let pool = SqlitePool::connect(&DBLocation::InMemory.sqlite_address("test"))
            .await
            .unwrap();

        MIGRATOR.run(&pool).await.unwrap();

        let scan_id = "itsamemario";
        let client_id = "Roehrich";
        let row = query(
            r#"
            INSERT INTO client_scan_map(scan_id, client_id) VALUES (?, ?)
            "#,
        )
        .bind(scan_id)
        .bind(client_id)
        .execute(&pool)
        .await
        .unwrap();
        let id = row.last_insert_rowid();
        let _ = query("INSERT INTO scans(id, status, host_all, host_queued, host_alive, host_dead) VALUES (?, 'running', 3, 0, 2, 1)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        super::set_scans_to_finished(&pool).await.unwrap();

        let status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(&status, "failed");
    }
}
