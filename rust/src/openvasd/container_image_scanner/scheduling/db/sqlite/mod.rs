// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use sqlx::SqlitePool;

use crate::database::dao::DAOHandler;

pub mod images;
pub mod preferences;
pub mod scan;
pub use crate::database::sqlite::results::DBResults;

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

impl<'o, T> DAOHandler<&'o DataBase, T> for DB<'o, T> {
    fn db(&self) -> &'o DataBase {
        self.pool
    }

    fn input(&self) -> &T {
        &self.input
    }

    fn inner(self) -> (&'o DataBase, T) {
        (self.pool, self.input)
    }
}

#[cfg(test)]
mod tests {
    use scannerlib::models::Phase;
    use sqlx::{SqlitePool, query, query_scalar};

    use crate::{
        config::DBLocation,
        container_image_scanner::{MIGRATOR, scheduling::db::scan::DBScan},
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
        let id = query("INSERT INTO scans(scan_id, client_id, status, auth_data, host_all, host_queued, host_alive, host_dead) VALUES (?, ?, 'running', '', 3, 0, 2, 1)")
            .bind(scan_id)
            .bind(client_id)
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();

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
