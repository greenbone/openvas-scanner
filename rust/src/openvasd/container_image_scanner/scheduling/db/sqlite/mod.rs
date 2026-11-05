// SPDX-FileCopyrightText: 2026 Greenbone AG
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
    use scannerlib::models::{self, Phase};
    use sqlx::{query, query_as, query_scalar};

    use crate::{
        config::SqliteConfiguration,
        container_image_scanner::{
            MIGRATOR,
            scans_utils::{create_pool, create_pool_with_version},
            scheduling::db::scan::DBScan,
        },
        crypt::{Crypt, Crypter, Encrypted},
        database::dao::RetryExec,
    };

    #[tokio::test]
    async fn test_migration() {
        // run all but the latest database migration
        let (pool, _guard) = create_pool_with_version(Some(20260227095952)).await;

        let id = query("INSERT INTO client_scan_map (scan_id, client_id) VALUES (?, ?)")
            .bind("scan1")
            .bind("client1")
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();

        query("INSERT INTO scans (id, status, host_all, host_queued, host_alive, host_dead) VALUES (?, 'stored', 0, 0, 0, 0)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();

        query("INSERT INTO credentials (id, username, password) VALUES (?, ?, ?)")
            .bind(id)
            .bind("user")
            .bind("pass")
            .execute(&pool)
            .await
            .unwrap();

        // run the rest of the migrations
        MIGRATOR.run(&pool).await.unwrap();
        let crypter = Crypter::from_config(&SqliteConfiguration::default(), &pool)
            .await
            .unwrap();

        let (oid, scan_id, client_id, auth_data): (i64, String, String, String) =
            query_as("SELECT id, scan_id, client_id, auth_data FROM scans WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(oid, id);
        assert_eq!(scan_id, "scan1");
        assert_eq!(client_id, "client1");

        let encrypted: Encrypted = Encrypted::try_from(auth_data).unwrap();
        let auth_data = crypter.decrypt(encrypted).await.unwrap();
        let credentials = serde_json::from_slice::<Vec<models::Credential>>(&auth_data).unwrap();

        assert_eq!(credentials.len(), 1);
        assert_eq!(
            credentials[0],
            models::Credential {
                service: models::Service::Generic,
                port: None,
                credential_type: models::CredentialType::UP {
                    username: "user".to_string(),
                    password: "pass".to_string(),
                    privilege: None
                }
            }
        )
    }

    #[tokio::test]
    async fn status_failed() {
        let (pool, _guard) = create_pool().await;

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
