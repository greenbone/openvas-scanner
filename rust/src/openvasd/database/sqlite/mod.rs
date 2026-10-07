use sqlx::Transaction;

use sqlx::{QueryBuilder, Sqlite, SqlitePool, query_builder::Separated};

use futures::Stream;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::{DBLocation, SqliteConfiguration, StorageType, StorageTypes};
use crate::crypt::Crypter;
use crate::database::dao::{DAOError, DAOHandler, DBViolation, InfrastructureReason};
use crate::{MIGRATOR, config};

pub mod cis;
pub mod results;
pub mod scan_storage;
pub mod scans;
pub mod state_change;
pub mod vts;

pub const SQLITE_LIMIT_VARIABLE_NUMBER: usize = 32766;

pub type DataBase = SqlitePool;

/// An async stream of Results used by the database.
pub type StreamResult<T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send>>;

#[derive(Clone)]
pub struct SqliteDatabase {
    pool: SqlitePool,
    crypter: Arc<Crypter>,
}

impl SqliteDatabase {
    // TODO: temp for testing which requires both the old and new pool
    pub async fn init_test(config: &config::Config, pool: SqlitePool) -> anyhow::Result<Arc<Self>> {
        let crypter = Arc::new(crate::scans::config_to_crypt(config, &pool).await?);
        Ok(Arc::new(Self { pool, crypter }))
    }

    pub async fn init(config: &config::Config) -> anyhow::Result<Arc<Self>> {
        let pool = match config.storage.clone() {
            StorageTypes::V1(storage_v1) => {
                let mut sqliteconfig = SqliteConfiguration::default();

                match storage_v1.storage_type {
                    StorageType::InMemory | StorageType::Redis => {}
                    StorageType::FileSystem if storage_v1.fs.path.is_dir() => {
                        let mut p = storage_v1.fs.path.clone();
                        p.push("openvasd.db");
                        sqliteconfig.location = DBLocation::File(p);
                    }
                    StorageType::FileSystem => {
                        sqliteconfig.location = DBLocation::File(storage_v1.fs.path);
                    }
                };
                sqliteconfig
            }
            StorageTypes::V2(sqlite_configuration) => sqlite_configuration,
        }
        .create_pool("openvasd")
        .await?;
        MIGRATOR.run(&pool).await?;
        let crypter = Arc::new(crate::scans::config_to_crypt(config, &pool).await?);

        Ok(Arc::new(Self { pool, crypter }))
    }

    pub async fn begin(&self) -> anyhow::Result<Transaction<'_, Sqlite>> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| e.into())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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
    F: for<'qb> FnMut(Separated<'qb, 'args, Sqlite, &'static str>, &'args T),
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
