use sqlx::Row;
use std::{collections::HashMap, sync::Arc};

use scannerlib::models;
use sqlx::{
    FromRow, IntoArguments, Sqlite, SqliteConnection, SqlitePool,
    query::{Query, QueryScalar},
    sqlite::{SqliteArguments, SqliteQueryResult, SqliteRow},
};
use tokio::sync::Mutex;

/// Contains a single connection to be used and allows replacing that connection on certain errors.
///
///
/// Unfortunately we have the issue that sqlite implementation of sqlx enforces DEFERRED mode,
/// meaning if another transaction hits the DB first it gets prioritized although another one was
/// started previously.
///
/// Additionally the implementation of SqliteConnection does not have a way to enforce an order
/// artificially and also doesn't allow cache control.
///
/// That's why we need to enforce for critical operations to happen on the same connection and
/// handled mutually exclusive usually enforced by a mutex.
struct SqliteConnectionContainer {
    pool: SqlitePool,
    current_connection: SqliteConnection,
    max_retries: usize,
}

macro_rules! retry_sql_connection_call {
    ($self:ident, $f:expr) => {{
        let mut tries = 0;
        loop {
            //sqlx::query("BEGIN IMMEDIATE").execute($self.connection()).await?;
            let result = $f($self.connection()).await;
            //sqlx::query("COMMIT").execute($self.connection()).await?;

            match result {
                Err(sqlx::Error::Io(io)) if tries < $self.max_retries => {
                    tracing::warn!(error=%io, "replace connection based on IO error");
                    $self.replace_connection().await?;
                    tries += 1;
                }
                other => {
                    return other;
                },
            }

        }
    }};
}

pub(crate) fn status_query<'a>(id: i64) -> Query<'a, Sqlite, SqliteArguments<'a>> {
    sqlx::query(r#"
        SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, host_scanning, status
        FROM scans
        WHERE id = ?
        "#)
        .bind(id)
}

pub(crate) fn row_to_models_status(scan_row: SqliteRow) -> models::Status {
    let excluded = scan_row.get("host_excluded");
    let dead = scan_row.get("host_dead");
    let alive = scan_row.get("host_alive");
    let finished = excluded + dead + alive;
    let host_scanning: String = scan_row.get("host_scanning");

    let host_progress: HashMap<String, i32> = host_scanning
        .split(',')
        .filter_map(|x| {
            if let Some((h, p)) = x.split_once('=') {
                Some((h.to_string(), p.parse::<i32>().unwrap()))
            } else {
                None
            }
        })
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

impl SqliteConnectionContainer {
    pub async fn init(pool: SqlitePool) -> Result<Self, sqlx::error::Error> {
        let current_connection = pool.acquire().await?.detach();
        Ok(Self {
            pool,
            current_connection,
            max_retries: 3,
        })
    }
    pub fn connection(&mut self) -> &mut SqliteConnection {
        &mut self.current_connection
    }

    async fn replace_connection(&mut self) -> Result<(), sqlx::error::Error> {
        self.current_connection = self.pool.acquire().await?.detach();
        use sqlx::Connection;
        self.current_connection.clear_cached_statements().await?;
        Ok(())
    }

    pub async fn fetch_one<'a, F, A>(&'a mut self, q: F) -> Result<SqliteRow, sqlx::error::Error>
    where
        F: Fn() -> Query<'a, Sqlite, A>,
        A: 'a + IntoArguments<'a, Sqlite>,
    {
        retry_sql_connection_call!(self, |c| q().fetch_one(c))
    }

    pub async fn fetch_one_scalar<'a, F, O, A>(&'a mut self, q: F) -> Result<O, sqlx::error::Error>
    where
        F: Fn() -> QueryScalar<'a, Sqlite, O, A>,
        O: Send + Unpin,
        A: 'a + IntoArguments<'a, Sqlite>,
        (O,): Send + Unpin + for<'r> FromRow<'r, SqliteRow>,
    {
        retry_sql_connection_call!(self, |c| q().fetch_one(c))
    }

    pub async fn fetch_all_scalar<'a, F, O, A>(
        &'a mut self,
        q: F,
    ) -> Result<Vec<O>, sqlx::error::Error>
    where
        F: Fn() -> QueryScalar<'a, Sqlite, O, A>,
        O: Send + Unpin,
        A: 'a + IntoArguments<'a, Sqlite>,
        (O,): Send + Unpin + for<'r> FromRow<'r, SqliteRow>,
    {
        retry_sql_connection_call!(self, |c| q().fetch_all(c))
    }

    pub async fn execute<'a, F, A>(
        &'a mut self,
        q: F,
    ) -> Result<SqliteQueryResult, sqlx::error::Error>
    where
        F: Fn() -> Query<'a, Sqlite, A>,
        A: 'a + IntoArguments<'a, Sqlite>,
    {
        retry_sql_connection_call!(self, |c| q().execute(c))
    }
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
        let result = row_to_models_status(row);
        Ok(result)
    }

    pub async fn scan_update_status(
        &self,
        id: i64,
        status: &models::Status,
    ) -> Result<(), ScanStateChangeError> {
        let host_info = status.host_info.clone().unwrap_or_default();

        let mut host_scanning = String::new();
        if let Some(scanning) = host_info.scanning {
            for (h, p) in scanning {
                host_scanning.push_str(format!("{}={},", h, p).as_str());
            }
        };

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
        host_scanning = COALESCE(NULLIF(?, ''), host_scanning),
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
            .bind(&host_scanning)
            .bind(status.status.as_ref())
            .bind(id)
        };

        self.connection_container.lock().await.execute(q).await?;

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
