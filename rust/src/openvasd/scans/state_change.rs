use std::{sync::Arc, time::Duration};

use scannerlib::models;
use sqlx::{
    FromRow, IntoArguments, Sqlite, SqliteConnection, SqlitePool,
    query::{Query, QueryScalar},
    sqlite::{SqliteQueryResult, SqliteRow},
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
    retry: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanStateChangeError {
    #[error("DB issue")]
    DB(#[from] sqlx::Error),
}

impl From<Arc<Mutex<SqliteConnectionContainer>>> for ScanStateController {
    fn from(value: Arc<Mutex<SqliteConnectionContainer>>) -> Self {
        Self {
            connection_container: value,
            retry: Duration::from_secs(1),
        }
    }
}

impl ScanStateController {
    pub async fn init(pool: SqlitePool) -> Result<Self, ScanStateChangeError> {
        let connection_container =
            Arc::new(Mutex::new(SqliteConnectionContainer::init(pool).await?));
        Ok(Self::from(connection_container))
    }

    // async fn block_on(&self, on: &str, mut ids: Vec<i64>) -> Result<(), ScanStateChangeError> {
    //     while !ids.is_empty() {
    //         let id = ids.first().unwrap();
    //         let q = || sqlx::query_scalar("SELECT status FROM scans WHERE id = ?").bind(id);
    //         let status: Option<String> = self
    //             .connection_container
    //             .lock()
    //             .await
    //             .fetch_one_scalar(q)
    //             .await?;
    //
    //         if status.as_deref() == Some(on) {
    //             ids.swap_remove(0);
    //         }
    //
    //         tokio::time::sleep(self.retry).await;
    //     }
    //     Ok(())
    // }
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

        //        self.block_on(to, vec![id]).await?;
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
        //self.block_on(to, rows).await?;
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
        let q = || crate::scans::status_query(id);
        let row = guard.fetch_one(q).await?;
        let result = crate::scans::row_to_models_status(row);
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
