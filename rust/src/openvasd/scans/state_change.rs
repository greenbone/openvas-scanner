use crate::database::sqlite::SqliteConnectionContainer;
use sqlx::{Row, query::QueryAs};
use std::{collections::HashMap, sync::Arc};

use scannerlib::models;
use sqlx::{
    FromRow, Sqlite, SqlitePool,
    query::Query,
    sqlite::{SqliteArguments, SqliteRow},
};
use tokio::sync::Mutex;

pub(crate) fn status_query<'a>(id: i64) -> Query<'a, Sqlite, SqliteArguments<'a>> {
    sqlx::query(r#"
        SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status
        FROM scans
        WHERE id = ?
        "#)
        .bind(id)
}

pub(crate) fn host_scanning_query<'a>(
    id: i64,
) -> QueryAs<'a, Sqlite, ScanningHost, SqliteArguments<'a>> {
    sqlx::query_as(
        r#"
        SELECT host_ip, progress
        FROM host_scanning
        WHERE id = ?
        "#,
    )
    .bind(id)
}

pub(crate) fn row_to_models_status(
    scan_row: SqliteRow,
    scanning_hosts_rows: Vec<ScanningHost>,
) -> models::Status {
    let excluded = scan_row.get("host_excluded");
    let dead = scan_row.get("host_dead");
    let alive = scan_row.get("host_alive");
    let finished = excluded + dead + alive;

    let host_progress: HashMap<String, i32> = scanning_hosts_rows
        .into_iter()
        .map(|sh| (sh.host_ip, sh.progress))
        .collect();

    let host_info = models::HostInfo {
        all: scan_row.get("host_all"),
        excluded,
        dead,
        alive,
        queued: scan_row.get("host_queued"),
        finished,
        scanning: Some(host_progress),
        remaining_vts_per_host: Default::default(),
    };
    models::Status {
        start_time: scan_row.get("start_time"),
        end_time: scan_row.get("end_time"),
        // should never fail as we just allow parseable values to be stored in the DB
        status: scan_row.get::<String, _>("status").parse().unwrap(),
        host_info: Some(host_info),
    }
}

#[derive(FromRow, Debug)]
pub struct ScanningHost {
    pub host_ip: String,
    pub progress: i32,
}

pub struct ScanStateController {
    connection_container: Arc<Mutex<SqliteConnectionContainer>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanStateChangeError {
    #[error("DB issue {0}")]
    DB(#[from] sqlx::Error),
}

impl From<Arc<Mutex<SqliteConnectionContainer>>> for ScanStateController {
    fn from(value: Arc<Mutex<SqliteConnectionContainer>>) -> Self {
        Self {
            connection_container: value,
        }
    }
}

impl ScanStateController {
    pub async fn init(pool: SqlitePool) -> Result<Self, ScanStateChangeError> {
        let connection_container =
            Arc::new(Mutex::new(SqliteConnectionContainer::init(pool).await?));
        Ok(Self::from(connection_container))
    }

    pub async fn change_state(
        &self,
        id: i64,
        from: &str,
        to: &str,
    ) -> Result<bool, ScanStateChangeError> {
        let query = || {
            sqlx::query("UPDATE scans SET status = ? WHERE status = ? AND id = ?")
                .bind(to)
                .bind(from)
                .bind(id)
        };

        let rows = self
            .connection_container
            .lock()
            .await
            .execute(query)
            .await?;
        tracing::debug!(
            affected = rows.rows_affected(),
            from,
            to,
            id,
            "Scan status change"
        );

        Ok(rows.rows_affected() > 0)
    }
    pub async fn change_state_all(
        &self,
        from: &str,
        to: &str,
    ) -> Result<usize, ScanStateChangeError> {
        let rows: Vec<i64> = self
            .connection_container
            .lock()
            .await
            .fetch_all_scalar(|| {
                sqlx::query_scalar("UPDATE scans SET status = ? WHERE status = ? RETURNING id")
                    .bind(to)
                    .bind(from)
            })
            .await?;
        let scans = rows.len();
        tracing::debug!(affected = scans, from, to, "Scans status change");
        Ok(scans)
    }

    pub async fn fetch_scans_in_state(
        &self,
        state: &str,
        limit: Option<i64>,
    ) -> Result<Vec<i64>, ScanStateChangeError> {
        self.connection_container
            .lock()
            .await
            .fetch_all_scalar(|| {
                sqlx::query_scalar("SELECT id FROM scans WHERE status = ? LIMIT ?")
                    .bind(state)
                    .bind(limit.unwrap_or(-1))
            })
            .await
            .map_err(ScanStateChangeError::from)
    }

    pub async fn scan_get_status(&self, id: i64) -> Result<models::Status, ScanStateChangeError> {
        let mut guard = self.connection_container.lock().await;
        let q = || status_query(id);
        let row = guard.fetch_one(q).await?;
        let q2 = || host_scanning_query(id);
        let rows: Vec<ScanningHost> = guard.fetch_all_rows(q2).await?;
        let result = row_to_models_status(row, rows);
        Ok(result)
    }

    pub async fn scan_update_status(
        &self,
        id: i64,
        status: &models::Status,
    ) -> Result<(), ScanStateChangeError> {
        let host_info = status.host_info.clone().unwrap_or_default();
        let q = || {
            sqlx::query(
                r#"
    UPDATE scans SET
        start_time    = COALESCE(?, start_time),
        end_time      = COALESCE(?, end_time),
        host_dead     = COALESCE(NULLIF(?, 0), host_dead),
        host_alive    = COALESCE(NULLIF(?, 0), host_alive),
        host_queued   = COALESCE(NULLIF(?, 0), host_queued),
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
        };
        self.connection_container.lock().await.execute(q).await?;

        let q = || sqlx::query(r#"DELETE from host_scanning WHERE id = ?"#).bind(id);
        self.connection_container.lock().await.execute(q).await?;

        if let Some(scanning) = host_info.scanning {
            for (h, p) in scanning {
                let q = || {
                    sqlx::query(
                        r#"INSERT INTO host_scanning (id, host_ip, progress) VALUES (?, ?, ?)"#,
                    )
                    .bind(id)
                    .bind(h.clone())
                    .bind(p)
                };

                self.connection_container.lock().await.execute(q).await?;
            }
        };

        Ok(())
    }

    pub async fn count_scans_in_state(&self, state: &str) -> Result<usize, ScanStateChangeError> {
        let result: Result<i64, _> = self
            .connection_container
            .lock()
            .await
            .fetch_one_scalar(|| {
                sqlx::query_scalar("SELECT count(id) FROM scans WHERE status = ?").bind(state)
            })
            .await;
        result
            .map(|x| x as usize)
            .map_err(ScanStateChangeError::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::scans::{
        state_change::ScanStateController,
        tests::{create_pool, prepare_scans},
    };

    #[tokio::test]
    async fn set_single_state() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let under_test = ScanStateController::init(pool.clone()).await?;

        let scans = prepare_scans(pool, &config).await;
        for scan in scans {
            under_test.change_state(scan, "stored", "requested").await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn set_all_scans() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let under_test = ScanStateController::init(pool.clone()).await?;
        let scans = prepare_scans(pool, &config).await;
        let affected = under_test.change_state_all("stored", "failed").await?;
        assert_eq!(affected, scans.len());
        Ok(())
    }
}
