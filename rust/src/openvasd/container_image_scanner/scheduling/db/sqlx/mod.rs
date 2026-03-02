use sqlx::SqlitePool;

pub mod images;
pub mod preferences;
pub mod results;
pub mod scan;
pub mod timed_layer;

pub type DataBase = SqlitePool;

#[derive(Debug, Clone)]
pub struct DB<'o, T> {
    pub input: T,
    pub pool: &'o DataBase,
}

impl<'o, T> DB<'o, T> {
    pub fn new(pool: &'o DataBase, input: T) -> DB<'o, T> {
        DB { input, pool }
    }
}

#[cfg(test)]
mod tests {
    use scannerlib::models::Phase;
    use sqlx::{SqlitePool, query, query_scalar};

    use crate::{
        container_image_scanner::{MIGRATOR, config::DBLocation, scheduling::db::scan::DBScan},
        database::dao::RetryExec,
    };

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

        DBScan::new(&pool, Phase::Succeeded)
            .retry_exec()
            .await
            .unwrap();

        let status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(&status, "failed");
    }
}
