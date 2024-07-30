use nasl_builtin_utils::FunctionErrorKind;
use thiserror::Error;

use crate::libssh::sessions::SessionId;

pub type Result<T> = std::result::Result<T, SshError>;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("Invalid SSH session ID: {0}")]
    InvalidSessionId(SessionId),
    #[error("Poisoned lock")]
    PoisonedLock,
    #[error("Failed to open a new channel for session ID {0}: {1}")]
    OpenChannel(SessionId, libssh_rs::Error),
    #[error("No available channel for session ID {0}")]
    NoAvailableChannel(SessionId),
    #[error("Channel unexpectedly closed for session ID {0}")]
    ChannelClosed(SessionId),
    #[error("Failed to request subsystem {2} for session ID {0}: {1}")]
    RequestSubsystem(SessionId, libssh_rs::Error, String),
    #[error("Failed to open session for session ID {0}: {1}")]
    OpenSession(SessionId, libssh_rs::Error),
    #[error("Failed to close channel for session ID {0}: {1}")]
    Close(SessionId, libssh_rs::Error),
    #[error("Failed to get server public key for session ID {0}: {1} ")]
    GetServerPublicKey(SessionId, libssh_rs::Error),
    #[error("Failed to get server banner for session ID {0}: {1} ")]
    GetServerBanner(SessionId, libssh_rs::Error),
    #[error("Failed to get issue banner for session ID {0}: {1} ")]
    GetIssueBanner(SessionId, libssh_rs::Error),
    #[error("Failed to set authentication to keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveInfo(SessionId, libssh_rs::Error),
    #[error("Failed to initiate keyboard-interactive authentication for session ID {0}: {1} ")]
    UserAuthKeyboardInteractive(SessionId, libssh_rs::Error),
    #[error("Failed to set answers for authentication via keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveSetAnswers(SessionId, libssh_rs::Error),
    #[error("Error while reading ssh for session ID {0}")]
    ReadSsh(SessionId),
}

impl From<SshError> for FunctionErrorKind {
    fn from(e: SshError) -> Self {
        FunctionErrorKind::Dirty(e.to_string())
    }
}
