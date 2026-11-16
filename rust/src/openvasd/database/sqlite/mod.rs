// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fs::Permissions;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;
use std::sync::Arc;

use scannerlib::SQLITE_LIMIT_VARIABLE_NUMBER;
use sqlx::Connection;

use sqlx::{
    Pool, QueryBuilder, Sqlite, SqliteConnection, SqlitePool, migrate::Migrator,
    query_builder::Separated,
};

use crate::config::{Config, DBLocation, SqliteConfiguration};
use crate::crypt::{Crypt, Crypter, Encrypted};
use crate::database::dao::{DAOError, DAOHandler, DBViolation, InfrastructureReason};

pub mod results;
pub mod scan_storage;
pub mod scans;
pub mod state_change;
pub mod vts;

pub type DataBase = SqlitePool;
pub type Transaction<'a> = sqlx::Transaction<'a, Sqlite>;

static MIGRATOR: Migrator = sqlx::migrate!();

pub async fn init(config: &Config) -> anyhow::Result<SqlitePool> {
    let pool = create_pool(&config.storage.to_sqlite_cfg(), "openvasd").await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

pub async fn create_pool(
    config: &crate::config::SqliteConfiguration,
    name: &str,
) -> anyhow::Result<Pool<Sqlite>> {
    use sqlx::{
        Sqlite,
        pool::PoolOptions,
        sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
    };

    if let Some(parent) = config.location.path(name)?.parent() {
        match std::fs::create_dir_all(parent) {
            Ok(_) => (),
            Err(e)
                if e.kind() == ErrorKind::AlreadyExists
                    && matches!(config.location, DBLocation::InMemory) =>
            {
                if let Err(e) = std::fs::remove_dir_all(parent) {
                    tracing::warn!("failed to cleanup database: {e}");
                }
            }
            Err(_) => return Err(anyhow::anyhow!("Failed to create dir at: {parent:?}")),
        }

        // Prevent access for anyone but the user
        std::fs::set_permissions(parent, Permissions::from_mode(0o700))?;
    }

    if config.max_connections.is_some() {
        tracing::warn!("The max_connections option has been deprecated");
    }

    // This setup supports 1 WRITE and N READ operations at the same time.
    // With WAL (Write-Ahead Logging) active each WRITE transaction is first written into a `-wal`
    // file before being transferred into the database at a checkout (which is not the commit).
    // This means that READ transactions can run at the same time and get the previous state of
    // the database.
    // If a second WRITE operation is trying to start it will wait for `busy_timeout` before failing.
    //
    // WARNING: The `busy_timeout` can be ignored by sqlite in situations when it is impossible to wait.
    // Instead the operation will fail immediately with an `SQLITE_BUSY` error.
    // This most importantly affects `DEFERRED` transactions that start with a READ statement and later
    // have to upgrade to a WRITE transaction.
    //
    // IF A TRANSACTION HAS TO WRITE DATA ALWAYS START AN IMMEDIATE TRANSACTION TO UTILIZE THE BUSY_TIMEOUT.
    let options = SqliteConnectOptions::from_str(&config.location.sqlite_address(name)?)?
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(config.busy_timeout)
        // Although this can lead to data loss in the case that the application crashes, we usually
        // need to restart that scan anyway.
        .synchronous(SqliteSynchronous::Off)
        .create_if_missing(true);

    // Due to the speed of /dev/shm the pool initialization can run into raceconditions.
    // That's why we use a throwaway connection to establish the database file first.
    let _ = SqliteConnection::connect_with(&options).await?;

    PoolOptions::<Sqlite>::new()
        // To prevent losing a in-memory DB we have to override max_lifetime and idle_timeout.
        // It seems that min_connections is not reliable enough for now to ensure at least one
        // connection being open.
        .max_lifetime(None)
        .idle_timeout(None)
        // scheduler + HTTP api
        .min_connections(2)
        .connect_with(options)
        .await
        .map_err(|e| e.into())
}

pub struct SqliteDatabase {
    pool: SqlitePool,
    crypter: Crypter,
}

impl SqliteDatabase {
    pub async fn init(config: &SqliteConfiguration, name: &str) -> anyhow::Result<Arc<Self>> {
        let pool = create_pool(config, name).await?;
        let crypter = Crypter::from_config(config, &pool).await?;

        Ok(Arc::new(Self { pool, crypter }))
    }

    /// Begins an IMMEDIATE transaction
    pub async fn tx(&self) -> anyhow::Result<Transaction<'_>> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| e.into())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub(super) async fn encrypt<T>(&self, input: &T) -> anyhow::Result<String>
    where
        T: serde::Serialize,
    {
        let bytes = serde_json::to_vec(input)?;
        Ok(self.crypter.encrypt(bytes).await?.to_string())
    }

    pub(super) async fn decrypt<T>(&self, input: &str) -> anyhow::Result<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let encrypted = Encrypted::try_from(input)?;
        let output = self.crypter.decrypt(encrypted).await?;
        serde_json::from_slice::<T>(&output).map_err(|e| e.into())
    }
}

impl Drop for SqliteDatabase {
    fn drop(&mut self) {
        let keep_failed_db =
            std::thread::panicking() && std::env::var("KEEP_TEST_DB").is_ok_and(|x| x == "true");

        if !keep_failed_db && let Some(path) = self.pool.connect_options().get_filename().parent() {
            let active_connections = self.pool.size().saturating_sub(self.pool.num_idle() as u32);
            if active_connections > 0 {
                tracing::debug!(active_connections, "DB connections active at shutdown");
            }

            if let Err(e) = std::fs::remove_dir_all(path) {
                tracing::warn!("failed to cleanup database: {e}");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct OpenVASDDB<'o, T> {
    pub input: T,
    pub pool: &'o DataBase,
}

impl<'o, T> OpenVASDDB<'o, T> {
    pub fn new(pool: &'o DataBase, input: T) -> OpenVASDDB<'o, T> {
        OpenVASDDB { input, pool }
    }
}

impl<'o, T> DAOHandler<&'o DataBase, T> for OpenVASDDB<'o, T> {
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

pub async fn insert_values_chunked<'args, T, E, F>(
    executor: &mut E,
    query: &str,
    mut push_value: F,
    values: &'args [T],
    num_args: usize,
) -> Result<(), sqlx::Error>
where
    for<'e> &'e mut E: sqlx::Executor<'e, Database = Sqlite>,
    F: for<'qb> FnMut(Separated<'qb, Sqlite, &'static str>, &'args T),
{
    if values.is_empty() {
        return Ok(());
    }

    if num_args == 0 {
        return Err(sqlx::Error::Protocol(
            "insert_values_chunked: num_args must be greater than zero".into(),
        ));
    }

    for chunk in values.chunks(SQLITE_LIMIT_VARIABLE_NUMBER / num_args) {
        let mut builder = QueryBuilder::new(query);
        builder.push_values(chunk, &mut push_value);
        let query = builder.build();
        query.execute(&mut *executor).await?;
    }

    Ok(())
}

impl From<sqlx::error::ErrorKind> for DBViolation {
    fn from(value: sqlx::error::ErrorKind) -> Self {
        match value {
            sqlx::error::ErrorKind::UniqueViolation => Self::UniqueViolation,
            sqlx::error::ErrorKind::ForeignKeyViolation => Self::ForeignKeyViolation,
            sqlx::error::ErrorKind::NotNullViolation => Self::NotNullViolation,
            sqlx::error::ErrorKind::CheckViolation => Self::CheckViolation,
            _ => Self::Unknown,
        }
    }
}

impl From<sqlx::Error> for DAOError {
    fn from(value: sqlx::Error) -> Self {
        use sqlx::error::ErrorKind::*;
        match &value {
            sqlx::Error::Database(be)
                if matches!(
                    be.kind(),
                    UniqueViolation | ForeignKeyViolation | NotNullViolation | CheckViolation
                ) =>
            {
                Self::DBViolation(be.kind().into())
            }
            sqlx::Error::Database(be) if be.code().is_some() => {
                let code: i64 = be
                    .code()
                    .map(|x| x.parse())
                    .filter(|x| x.is_ok())
                    .map(|x| x.unwrap())
                    .unwrap_or_default();
                // 5,   https://sqlite.org/rescode.html#busy
                // 6,   https://sqlite.org/rescode.html#locked
                // 513, https://sqlite.org/rescode.html#error_retry
                // 517, https://sqlite.org/rescode.html#busy_snapshot
                // 773, https://sqlite.org/rescode.html#busy_timeout

                Self::Infrastructure(match code {
                    5 | 517 | 773 => InfrastructureReason::Busy,
                    6 => InfrastructureReason::Locked,
                    513 => InfrastructureReason::RetryError(value.to_string()),
                    _ => InfrastructureReason::Error(value.to_string()),
                })
            }
            sqlx::Error::RowNotFound => DAOError::NotFound,
            error => {
                tracing::warn!(%error, "Unexpected sqlx::Error.");
                DAOError::Infrastructure(InfrastructureReason::Error(value.to_string()))
            }
        }
    }
}

pub struct DbGuard {
    pool: SqlitePool,
}

impl DbGuard {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl Drop for DbGuard {
    fn drop(&mut self) {
        let keep_failed_db =
            std::thread::panicking() && std::env::var("KEEP_TEST_DB").is_ok_and(|x| x == "true");

        if !keep_failed_db && let Some(path) = self.pool.connect_options().get_filename().parent() {
            let active_connections = self.pool.size().saturating_sub(self.pool.num_idle() as u32);
            if active_connections > 0 {
                tracing::debug!(active_connections, "DB connections active at shutdown");
            }

            if let Err(e) = std::fs::remove_dir_all(path) {
                tracing::warn!("failed to cleanup database: {e}");
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    use sqlx::{
        Sqlite, SqlitePool, migrate::Migrator, pool::PoolOptions, sqlite::SqliteConnectOptions,
    };

    use crate::{
        config::DBLocation,
        database::sqlite::{DbGuard, MIGRATOR},
    };

    pub async fn create_test_pool(
        name: &str,
        migrator: &Migrator,
        version: Option<i64>,
    ) -> (SqlitePool, DbGuard) {
        if let Some(parent) = DBLocation::InMemory.path(name).unwrap().parent() {
            std::fs::create_dir_all(parent).expect("expected database directory in shm")
        }

        let options =
            SqliteConnectOptions::from_str(&DBLocation::InMemory.sqlite_address(name).unwrap())
                .unwrap()
                .create_if_missing(true);

        let pool = PoolOptions::<Sqlite>::new()
            .connect_with(options)
            .await
            .expect("inmemory database must be available");

        if let Some(version) = version {
            migrator
                .run_to(version, &pool)
                .await
                .expect("need migrated database scheme");
        } else {
            migrator
                .run(&pool)
                .await
                .expect("need migrated database scheme");
        };

        let guard = DbGuard::new(pool.clone());
        (pool, guard)
    }

    async fn create_pool_with_version(version: i64) -> (SqlitePool, DbGuard) {
        create_test_pool("openvasd", &super::MIGRATOR, Some(version)).await
    }

    #[tokio::test]
    async fn test_migration() {
        // run all but the latest database migration
        let (pool, _guard) = create_pool_with_version(20261001130000).await;

        let id = sqlx::query("INSERT INTO client_scan_map (scan_id, client_id) VALUES (?, ?)")
            .bind("scan1")
            .bind("client1")
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();

        sqlx::query("INSERT INTO scans (id, auth_data, status, host_all, host_queued, host_alive, host_dead) VALUES (?, '', 'stored', 0, 0, 0, 0)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        // run the rest of the migrations
        MIGRATOR.run(&pool).await.unwrap();

        let (oid, scan_id, client_id): (i64, String, String) =
            sqlx::query_as("SELECT id, scan_id, client_id FROM scans WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(oid, id);
        assert_eq!(scan_id, "scan1");
        assert_eq!(client_id, "client1");
    }
}
