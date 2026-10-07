use crate::database::sqlite::SqliteDatabase;
use sqlx::{Row, Transaction, query::QueryAs};
use std::collections::HashMap;

use scannerlib::models;
use sqlx::{
    FromRow, Sqlite,
    query::Query,
    sqlite::{SqliteArguments, SqliteRow},
};

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

impl SqliteDatabase {
    // pub async fn change_state_all(&self, from: &str, to: &str) -> anyhow::Result<usize> {
    //     let rows: Vec<i64> = self
    //         .connection_container
    //         .lock()
    //         .await
    //         .fetch_all_scalar(|| {
    //             sqlx::query_scalar("UPDATE scans SET status = ? WHERE status = ? RETURNING id")
    //                 .bind(to)
    //                 .bind(from)
    //         })
    //         .await?;
    //     let scans = rows.len();
    //     tracing::debug!(affected = scans, from, to, "Scans status change");
    //     Ok(scans)
    // }

    // pub async fn fetch_scans_in_state(
    //     &self,
    //     state: &str,
    //     limit: Option<i64>,
    // ) -> Result<Vec<i64>, ScanStateChangeError> {
    //     self.connection_container
    //         .lock()
    //         .await
    //         .fetch_all_scalar(|| {
    //             sqlx::query_scalar("SELECT id FROM scans WHERE status = ? LIMIT ?")
    //                 .bind(state)
    //                 .bind(limit.unwrap_or(-1))
    //         })
    //         .await
    //         .map_err(ScanStateChangeError::from)
    // }

    pub(super) async fn scan_get_status(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        id: i64,
    ) -> anyhow::Result<models::Status> {
        let row = sqlx::query(r#"
            SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status
            FROM scans
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;

        let rows: Vec<ScanningHost> = sqlx::query_as(
            r#"
            SELECT host_ip, progress
            FROM host_scanning
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await?;

        let result = row_to_models_status(row, rows);
        Ok(result)
    }

    pub(super) async fn scan_update_status(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
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
        .execute(&mut **tx)
        .await?;

        sqlx::query("DELETE from host_scanning WHERE id = ?")
            .bind(id)
            .execute(&mut **tx)
            .await?;

        if let Some(scanning) = host_info.scanning {
            for (h, p) in scanning {
                sqlx::query("INSERT INTO host_scanning (id, host_ip, progress) VALUES (?, ?, ?)")
                    .bind(id)
                    .bind(h.clone())
                    .bind(p)
                    .execute(&mut **tx)
                    .await?;
            }
        };

        Ok(())
    }

    // pub async fn count_scans_in_state(&self, state: &str) -> Result<usize, ScanStateChangeError> {
    //     let result: Result<i64, _> = self
    //         .connection_container
    //         .lock()
    //         .await
    //         .fetch_one_scalar(|| {
    //             sqlx::query_scalar("SELECT count(id) FROM scans WHERE status = ?").bind(state)
    //         })
    //         .await;
    //     result
    //         .map(|x| x as usize)
    //         .map_err(ScanStateChangeError::from)
    // }
}

#[cfg(test)]
mod tests {
    // TODO: reintroduce
    // use crate::database::sqlite::state_change::ScanStateController;
    // use crate::scans::tests::{create_pool, prepare_scans};

    // #[tokio::test]
    // async fn set_single_state() -> anyhow::Result<()> {
    //     let (config, pool) = create_pool().await?;
    //     let under_test = ScanStateController::init(pool.clone()).await?;

    //     let scans = prepare_scans(pool, &config).await;
    //     for scan in scans {
    //         under_test.change_state(scan, "stored", "requested").await?;
    //     }
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn set_all_scans() -> anyhow::Result<()> {
    //     let (config, pool) = create_pool().await?;
    //     let under_test = ScanStateController::init(pool.clone()).await?;
    //     let scans = prepare_scans(pool, &config).await;
    //     let affected = under_test.change_state_all("stored", "failed").await?;
    //     assert_eq!(affected, scans.len());
    //     Ok(())
    // }
}
