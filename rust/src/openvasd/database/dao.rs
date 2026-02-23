use std::pin::Pin;

use scannerlib::{Promise, PromiseRef, Streamer};

#[derive(Debug, Clone, thiserror::Error)]
pub enum DAOError {
    #[error("Unique constraint violation")]
    UniqueConstraintViolation,

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
pub type DAOPromise<T> = Promise<Result<T, DAOError>>;
pub type DAOResult<T> = Result<T, DAOError>;

pub trait Insert {
    fn insert<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b;
}

pub trait Fetch<T> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, T>
    where
        'a: 'b;
}

pub trait StreamFetch<T> {
    fn stream_fetch(self) -> DAOStreamer<T>;
}
