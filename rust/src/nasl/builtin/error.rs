use thiserror::Error;

use super::{ssh::SshError, string::StringError};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BuiltinError {
    #[error("Authentication error.")]
    Authentication,
    #[error("{0}")]
    Ssh(SshError),
    #[error("{0}")]
    String(StringError),
}
