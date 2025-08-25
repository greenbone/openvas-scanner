use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RpmdbError {
    #[error(transparent)]
    Rusqlite(#[from] rusqlite::Error),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Bincode(#[from] bincode::Error),

    #[error("invalid sqlite file")]
    InvalidSqliteFile,

    #[error("invalid ndb file")]
    InvalidNdbFile,

    #[error("failed to parse ndb file: {0}")]
    ParseNdbFile(String),

    #[error("failed to parse bdb file: {0}")]
    ParseBdbFile(String),

    #[error("failed to parse blob: {0}")]
    ParseBlob(String),

    #[error("failed to parse entry: {0}")]
    ParseEntry(String),
}
