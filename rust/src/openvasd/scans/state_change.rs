use std::{sync::Arc, time::Duration};

use sqlx::{SqlitePool, query, query_scalar};
use tokio::sync::Mutex;

pub struct ScanStateChange {
    guard: Arc<Mutex<()>>,
    pool: SqlitePool,
    retry: Duration,
}

impl From<SqlitePool> for ScanStateChange {
    fn from(value: SqlitePool) -> Self {
        Self {
            guard: Arc::new(Mutex::new(())),
            pool: value,
            retry: Duration::from_micros(200),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanStateChangeError {
    #[error("DB issue")]
    DB(#[from] sqlx::Error),
}

impl ScanStateChange {
    async fn block_on(&self, on: &str, mut ids: Vec<i64>) -> Result<(), ScanStateChangeError> {
        while !ids.is_empty() {
            let id = ids.first().unwrap();
            let status: Option<String> =
                sqlx::query_scalar("SELECT status FROM scans WHERE id = ?")
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?;

            if status.as_deref() == Some(on) {
                ids.swap_remove(0);
            }

            tokio::time::sleep(self.retry).await;
        }
        Ok(())
    }
    pub async fn change_state(
        &self,
        id: i64,
        from: &str,
        to: &str,
    ) -> Result<bool, ScanStateChangeError> {
        dbg!(id, from, to);
        let _guard = self.guard.lock().await;
        let rows = query("UPDATE scans SET status = ? WHERE status = ? AND id = ?")
            .bind(to)
            .bind(from)
            .bind(id)
            .execute(&self.pool)
            .await?;
        tracing::debug!(
            affected = rows.rows_affected(),
            from,
            to,
            id,
            "Scan status change"
        );

        self.block_on(to, vec![id]).await?;
        Ok(rows.rows_affected() > 0)
    }
    pub async fn change_state_all(
        &self,
        from: &str,
        to: &str,
    ) -> Result<usize, ScanStateChangeError> {
        let _guard = self.guard.lock().await;
        let rows: Vec<i64> =
            query_scalar("UPDATE scans SET status = ? WHERE status = ? RETURNING id")
                .bind(to)
                .bind(from)
                .fetch_all(&self.pool)
                .await?;
        let scans = rows.len();
        tracing::debug!(affected = scans, from, to, "Scans status change");
        self.block_on(to, rows).await?;
        Ok(scans)
    }
}

#[cfg(test)]
mod tests {
    use crate::scans::{
        state_change::ScanStateChange,
        tests::{create_pool, prepare_scans},
    };

    #[tokio::test]
    async fn set_single_state() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let under_test: ScanStateChange = pool.clone().into();
        let scans = prepare_scans(pool, &config).await;
        for scan in scans {
            under_test.change_state(scan, "stored", "requested").await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn set_all_scans() -> crate::Result<()> {
        let (config, pool) = create_pool().await?;
        let under_test: ScanStateChange = pool.clone().into();
        let scans = prepare_scans(pool, &config).await;
        let affected = under_test.change_state_all("stored", "failed").await?;
        assert_eq!(affected, scans.len());
        Ok(())
    }
}
