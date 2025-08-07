use std::sync::Arc;

use greenbone_scanner_framework::models::Scan;
use scannerlib::scanner::{ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper};
use sqlx::{SqlitePool, query, query_scalar, sqlite::SqliteArguments};

use crate::crypt::Crypt;
mod nasl;

pub struct ScanScheduler<Scanner, Cryptor> {
    pool: SqlitePool,
    cryptor: Arc<Cryptor>,
    scanner: Arc<Scanner>,
    max_concurrent_scan: usize,
}

pub enum Message {
    Start(String),
    // On Stop we also delete
    Stop(String),
}

type R<T> = Result<T, Box<dyn std::error::Error>>;

impl<T, C> ScanScheduler<T, C> {
    /// Should be called on restart if the application crashed while there were running scans.
    ///
    /// This is to safe guard against ghost scans that will never finish.
    async fn running_to_failed(&self) -> R<()> {
        let rows = query("UPDATE scans SET status = 'failed' WHERE status = 'running'")
            .execute(&self.pool)
            .await?;

        tracing::warn!(
            scans_failed = rows.rows_affected(),
            "Set scans to failed from previous runs."
        );
        Ok(())
    }

    async fn stored_to_requested(&self, id: i64) -> R<()> {
        let row = query("UPDATE scans SET status = 'requested' WHERE id = ? AND status = 'stored'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if row.rows_affected() > 0 {
            tracing::debug!(id, "Changed scan from stored to requested");
        } else {
            tracing::info!(
                id,
                "Unable to change scan from stored to requested because the status is not in stored."
            );
        }
        Ok(())
    }
}

impl<Scanner, C> ScanScheduler<Scanner, C>
where
    Scanner: ScanStarter + ScanStopper + ScanDeleter + ScanResultFetcher + Send + Sync + 'static,
    C: Crypt + Send + Sync + 'static,
{
    /// Returns freshly switched scans that moved from requested to running
    ///
    /// The idea is to call this method to get the scans that will be started, hand them over the
    /// the actual scanner implementation.
    ///
    /// Later on we will get all hosts that are oci:// and hand them over the a separate scanner
    /// implementation
    async fn requested_to_running(&self) -> R<()> {
        let mut tx = self.pool.begin().await?;

        let ids: Vec<i64> = sqlx::query_scalar(
            r#"
        WITH running_count AS (
            SELECT COUNT(*) AS running_total
            FROM scans
            WHERE status = 'running'
        )
        SELECT id
        FROM scans
        WHERE status = 'requested'
        ORDER BY created_at ASC
        LIMIT (
            SELECT GREATEST($1 - running_total, 0)
            FROM running_count
        )
        "#,
        )
        .bind(self.max_concurrent_scan as i64)
        .fetch_all(&mut *tx)
        .await?;
        for id in ids {
            if !self.scanner.can_start_scan().await {
                break;
            }

            let scan = super::get_scan(&mut tx, self.cryptor.as_ref(), id).await?;
            match self.scanner.start_scan(scan).await {
                Ok(()) => {
                    let row = query("UPDATE scans SET status = 'running' WHERE id = ?")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                    tracing::info!(id, running = row.rows_affected(), "Started scan");
                }
                Err(error) => {
                    tracing::warn!(id, %error, "Unable to start scan");
                    query("UPDATE scans SET status = 'failed' WHERE id = ?")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }

        tx.commit().await?;

        Ok(())
    }

    async fn on_message(&self, message: Message) -> R<()> {
        match message {
            Message::Start(id) => self.stored_to_requested(id.parse()?).await?,
            Message::Stop(id) => todo!(),
        };
        Ok(())
    }
}
