use thiserror::Error;

use crate::nasl::FunctionErrorKind;

use super::SessionId;

pub type Result<T> = std::result::Result<T, SshError>;

#[cfg(feature = "nasl-builtin-libssh")]
type LibError = libssh_rs::Error;
#[cfg(not(feature = "nasl-builtin-libssh"))]
type LibError = russh::Error;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("Failed to open new SSH session: {0}")]
    NewSession(LibError),
    #[error("Invalid SSH session ID: {0}")]
    InvalidSessionId(SessionId),
    #[error("Poisoned lock")]
    PoisonedLock,
    #[error("Failed to connect for session ID {0}: {1}")]
    Connect(SessionId, LibError),
    #[error("Failed to open a new channel for session ID {0}: {1}")]
    OpenChannel(SessionId, LibError),
    #[error("No available channel for session ID {0}")]
    NoAvailableChannel(SessionId),
    #[error("Channel unexpectedly closed for session ID {0}")]
    ChannelClosed(SessionId),
    #[error("Failed to request subsystem {2} for session ID {0}: {1}")]
    RequestSubsystem(SessionId, LibError, String),
    #[error("Failed to open session for session ID {0}: {1}")]
    OpenSession(SessionId, LibError),
    #[error("Failed to close channel for session ID {0}: {1}")]
    Close(SessionId, LibError),
    #[error("Error while requesting pty for session ID {0}: {1}")]
    RequestPty(SessionId, LibError),
    #[error("Error while requesting command execution for session ID {0}: {1}")]
    RequestExec(SessionId, LibError),
    #[error("Error while requesting shell for session ID {0}: {1}")]
    RequestShell(SessionId, LibError),
    #[error("Failed to get server public key for session ID {0}: {1} ")]
    GetServerPublicKey(SessionId, LibError),
    #[error("Failed to get server banner for session ID {0}: {1} ")]
    GetServerBanner(SessionId, LibError),
    #[error("Failed to get issue banner for session ID {0}: {1} ")]
    GetIssueBanner(SessionId, LibError),
    #[error("Failed to set SSH option {1:?} for session ID: {0}: {2}")]
    SetOption(SessionId, String, LibError),
    #[error("Failed to set authentication to keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveInfo(SessionId, LibError),
    #[error("Failed to initiate keyboard-interactive authentication for session ID {0}: {1} ")]
    UserAuthKeyboardInteractive(SessionId, LibError),
    #[error("Failed to set answers for authentication via keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveSetAnswers(SessionId, LibError),
    #[error("Failed to authenticate via password for session ID {0}: {1} ")]
    UserAuthPassword(SessionId, LibError),
    #[error("Failed to perform 'none' authentication for session ID {0}: {1} ")]
    UserAuthNone(SessionId, LibError),
    #[error("Failed to request list of authentication methods for session ID {0}: {1} ")]
    UserAuthList(SessionId, LibError),
    #[error(
        "Failed to check whether public key authentication is possible for session ID {0}: {1} "
    )]
    UserAuthTryPublicKey(SessionId, LibError),
    #[error("Failed to authenticate with public key for session ID {0}: {1} ")]
    UserAuthPublicKey(SessionId, LibError),
    #[error("Error while reading ssh for session ID {0}")]
    ReadSsh(SessionId),
    #[error("Error while initiating sftp for session ID {0}: {1}")]
    Sftp(SessionId, LibError),
}

impl From<SshError> for FunctionErrorKind {
    fn from(e: SshError) -> Self {
        FunctionErrorKind::Dirty(e.to_string())
    }
}
