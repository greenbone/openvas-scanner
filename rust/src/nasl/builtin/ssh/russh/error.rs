use super::{FunctionErrorKind, SessionId};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SshError>;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("Invalid SSH session ID: {0}")]
    InvalidSessionId(SessionId),
    #[error("Failed to connect in session ID: {0}. {1}")]
    Connect(SessionId, russh::Error),
}

impl From<SshError> for FunctionErrorKind {
    fn from(e: SshError) -> Self {
        FunctionErrorKind::Dirty(e.to_string())
    }
}
