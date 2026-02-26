use std::{fmt::Display, time::Duration};

use scannerlib::{PromiseRef, Streamer};

#[derive(Debug, Clone, Copy)]
pub enum DBViolation {
    UniqueViolation,
    ForeignKeyViolation,
    NotNullViolation,
    CheckViolation,
    Unknown,
}

impl AsRef<str> for DBViolation {
    fn as_ref(&self) -> &str {
        match self {
            DBViolation::UniqueViolation => "UniqueViolation",
            DBViolation::ForeignKeyViolation => "ForeignKeyViolation",
            DBViolation::NotNullViolation => "NotNullViolation",
            DBViolation::CheckViolation => "CheckViolation",
            DBViolation::Unknown => "Unknown",
        }
    }
}

impl Display for DBViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}
// 5,   // https://sqlite.org/rescode.html#busy
// 6,   // https://sqlite.org/rescode.html#locked
// 513, // https://sqlite.org/rescode.html#error_retry
// 517, // https://sqlite.org/rescode.html#busy_snapshot
// 773, // https://sqlite.org/rescode.html#busy_timeout
//

#[derive(Debug, Clone)]
pub enum InfrastructureReason {
    Busy,
    Locked,
    RetryError(String),
    Error(String),
}

impl InfrastructureReason {
    pub fn is_retryable(&self) -> bool {
        !matches!(self, Self::Error(_))
    }

    pub fn is_reconnect(&self) -> bool {
        !self.is_retryable()
    }
}

impl Display for InfrastructureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InfrastructureReason::Busy => write!(f, "busy"),
            InfrastructureReason::Locked => write!(f, "locked"),
            InfrastructureReason::RetryError(s) => write!(f, "retry: {}", s),
            InfrastructureReason::Error(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DAOError {
    #[error("DB violation: {0}")]
    DBViolation(DBViolation),
    #[error("Not found")]
    NotFound,
    #[error("Corrupt data")]
    Corrupt,

    #[error("DB: {0}")]
    Infrastructure(InfrastructureReason),
}

impl DAOError {
    pub fn is_retryable(&self) -> bool {
        if let Self::Infrastructure(reason) = self {
            reason.is_retryable()
        } else {
            false
        }
    }

    pub fn is_reconnect(&self) -> bool {
        if let Self::Infrastructure(reason) = self {
            reason.is_reconnect()
        } else {
            false
        }
    }
}

pub type DAOPromiseRef<'a, T> = PromiseRef<'a, Result<T, DAOError>>;
pub type DAOStreamer<T> = Streamer<Result<T, DAOError>>;
// pub type DAOPromise<T> = Promise<Result<T, DAOError>>;
// pub type DAOResult<T> = Result<T, DAOError>;

pub trait Insert {
    fn insert<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b;
}

pub trait Delete {
    fn delete<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b;
}

pub trait Fetch<T> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, T>
    where
        'a: 'b;
}

pub trait Execute<T> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, T>
    where
        'a: 'b;
}

const MAX_RETRIES: u8 = 5;
pub fn calculate_sleep_based_on(retries: u8) -> Duration {
    let seconds = (MAX_RETRIES - retries) as u64;
    Duration::from_secs(seconds)
}
fn retry_ref<'a, F, T>(f: F) -> DAOPromiseRef<'a, T>
where
    T: Send,
    F: Fn() -> DAOPromiseRef<'a, T> + Send + 'a,
{
    Box::pin(async move {
        let mut last_resort = f().await;
        for i in 1..MAX_RETRIES {
            match &last_resort {
                Ok(_) => break,
                Err(x) if x.is_retryable() => {
                    tracing::debug!(error=?x, "Retrying");
                    tokio::time::sleep(calculate_sleep_based_on(i)).await;
                }
                Err(_) => break,
            };
            last_resort = f().await;
        }
        // Cut my life into pieces, this is my
        last_resort
    })
}

pub trait RetryExec<T>: Execute<T>
where
    T: Send,
{
    fn retry_exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, T>
    where
        'a: 'b,
        Self: Sync,
    {
        retry_ref(|| self.exec())
    }
}

impl<O, T> RetryExec<T> for O
where
    T: Send,
    O: Sync + Execute<T>,
{
}

pub trait StreamFetch<T> {
    fn stream_fetch(self) -> DAOStreamer<T>;
}
