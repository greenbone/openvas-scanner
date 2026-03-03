use sqlx::query::QueryAs;

use sqlx::{
    FromRow, IntoArguments, Sqlite, SqliteConnection, SqlitePool,
    query::{Query, QueryScalar},
    sqlite::{SqliteQueryResult, SqliteRow},
};

use crate::database::dao::{DAOError, DAOHandler, DBViolation, InfrastructureReason};

pub mod results;
pub mod scans;
pub mod state_change;
pub mod vts;

pub type DataBase = SqlitePool;

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
///
///
#[derive(Debug)]
pub struct SqliteConnectionContainer {
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

    pub async fn fetch_all_rows<'a, F, O, A>(
        &'a mut self,
        q: F,
    ) -> Result<Vec<O>, sqlx::error::Error>
    where
        F: Fn() -> QueryAs<'a, Sqlite, O, A>,
        A: 'a + IntoArguments<'a, Sqlite>,
        O: Send + Unpin + for<'r> FromRow<'r, SqliteRow>,
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
