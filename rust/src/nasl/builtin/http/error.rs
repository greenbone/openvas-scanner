use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("IO error during HTTP: {0}")]
    IO(io::ErrorKind),
    #[error("HTTP error: {0}")]
    H2(String),
    #[error("Handle ID {0} not found.")]
    HandleIdNotFound(i32),
}

impl From<io::Error> for HttpError {
    fn from(value: io::Error) -> Self {
        Self::IO(value.kind())
    }
}

impl From<h2::Error> for HttpError {
    fn from(value: h2::Error) -> Self {
        Self::H2(format!("{}", value))
    }
}
