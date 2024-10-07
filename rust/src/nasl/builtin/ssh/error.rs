use thiserror::Error;

use crate::nasl::FunctionErrorKind;

use super::SessionId;

pub type Result<T> = std::result::Result<T, SshError>;

#[cfg(feature = "nasl-builtin-libssh")]
#[derive(Debug, Error)]
pub enum SshError {
    #[error("Failed to open new SSH session: {0}")]
    NewSession(libssh_rs::Error),
    #[error("Invalid SSH session ID: {0}")]
    InvalidSessionId(SessionId),
    #[error("Poisoned lock")]
    PoisonedLock,
    #[error("Failed to connect for session ID {0}: {1}")]
    Connect(SessionId, libssh_rs::Error),
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
    #[error("Error while requesting pty for session ID {0}: {1}")]
    RequestPty(SessionId, libssh_rs::Error),
    #[error("Error while requesting command execution for session ID {0}: {1}")]
    RequestExec(SessionId, libssh_rs::Error),
    #[error("Error while requesting shell for session ID {0}: {1}")]
    RequestShell(SessionId, libssh_rs::Error),
    #[error("Failed to get server public key for session ID {0}: {1} ")]
    GetServerPublicKey(SessionId, libssh_rs::Error),
    #[error("Failed to get server banner for session ID {0}: {1} ")]
    GetServerBanner(SessionId, libssh_rs::Error),
    #[error("Failed to get issue banner for session ID {0}: {1} ")]
    GetIssueBanner(SessionId, libssh_rs::Error),
    #[error("Failed to set SSH option {1:?} for session ID: {0}: {2}")]
    SetOption(SessionId, String, libssh_rs::Error),
    #[error("Failed to set authentication to keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveInfo(SessionId, libssh_rs::Error),
    #[error("Failed to initiate keyboard-interactive authentication for session ID {0}: {1} ")]
    UserAuthKeyboardInteractive(SessionId, libssh_rs::Error),
    #[error("Failed to set answers for authentication via keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveSetAnswers(SessionId, libssh_rs::Error),
    #[error("Failed to authenticate via password for session ID {0}: {1} ")]
    UserAuthPassword(SessionId, libssh_rs::Error),
    #[error("Failed to perform 'none' authentication for session ID {0}: {1} ")]
    UserAuthNone(SessionId, libssh_rs::Error),
    #[error("Failed to request list of authentication methods for session ID {0}: {1} ")]
    UserAuthList(SessionId, libssh_rs::Error),
    #[error(
        "Failed to check whether public key authentication is possible for session ID {0}: {1} "
    )]
    UserAuthTryPublicKey(SessionId, libssh_rs::Error),
    #[error("Failed to authenticate with public key for session ID {0}: {1} ")]
    UserAuthPublicKey(SessionId, libssh_rs::Error),
    #[error("Error while reading ssh for session ID {0}")]
    ReadSsh(SessionId),
    #[error("Error while initiating sftp for session ID {0}: {1}")]
    Sftp(SessionId, libssh_rs::Error),
}

#[cfg(not(feature = "nasl-builtin-libssh"))]
#[derive(Debug, Error)]
pub enum SshError {}

impl From<SshError> for FunctionErrorKind {
    fn from(e: SshError) -> Self {
        FunctionErrorKind::Dirty(e.to_string())
    }
}
