use thiserror::Error;

use super::ssh::SshError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BuiltinError {
    #[error("Authentication error.")]
    Authentication,
    #[error("{0}")]
    Ssh(SshError),
}
