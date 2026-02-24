use std::fmt::Display;

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

#[derive(Debug, Clone, thiserror::Error)]
pub enum DAOError {
    #[error("DB violation: {0}")]
    DBViolation(DBViolation),
    #[error("Not found")]
    NotFound,
    #[error("Corrupt data")]
    Corrupt,
    #[error("Infrastructure")]
    Infrastructure,
}

impl DAOError {
    pub fn is_retryable(&self) -> bool {
        false
    }

    pub fn is_reconnect(&self) -> bool {
        matches!(self, DAOError::Infrastructure)
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

pub trait StreamFetch<T> {
    fn stream_fetch(self) -> DAOStreamer<T>;
}
