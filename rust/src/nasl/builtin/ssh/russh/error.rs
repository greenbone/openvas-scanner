use std::net::AddrParseError;

use super::{FunctionErrorKind, SessionId};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SshError>;

/// A cloneable representation of the russh Error
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct RusshError(String);

impl From<russh::Error> for RusshError {
    fn from(e: russh::Error) -> Self {
        Self(format!("{}", e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SshError {
    #[error("Invalid SSH session ID: {0}")]
    InvalidSessionId(SessionId),
    #[error("Failed to parse IP address '{0}' with error {1}")]
    InvalidIpAddr(String, AddrParseError),
    #[error("Failed to connect for session ID {0}: {1}")]
    Connect(SessionId, RusshError),
    #[error("Invalid keytype: '{0}'")]
    InvalidKeytype(String),
    #[error("Invalid cipher: '{0}'")]
    InvalidCipher(String),
    #[error("Error while executing command '{1}' in session id {0}: {2}")]
    CallError(SessionId, String, RusshError),
    #[error("Attempted to authenticate without authentication data given for session ID: {0}")]
    NoAuthenticationGiven(SessionId),
    #[error("Error while authenticating with password for session ID {0}")]
    UserauthPassword(SessionId),
    #[error("Error while authenticating with keyboard-interactive for session ID {0}")]
    UserauthKeyboardInteractive(SessionId),
}

impl From<SshError> for FunctionErrorKind {
    fn from(e: SshError) -> Self {
        FunctionErrorKind::Ssh(e)
    }
}
