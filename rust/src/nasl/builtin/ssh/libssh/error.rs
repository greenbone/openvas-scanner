use thiserror::Error;

use crate::nasl::FunctionErrorKind;

use super::SessionId;

pub type Result<T> = std::result::Result<T, SshError>;

/// A cloneable representation of the libssh_rs Error
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct LibSshError(String);

impl From<libssh_rs::Error> for LibSshError {
    fn from(e: libssh_rs::Error) -> Self {
        Self(format!("{}", e))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SshError {
    #[error("Failed to open new SSH session: {0}")]
    NewSession(LibSshError),
    #[error("Invalid SSH session ID: {0}")]
    InvalidSessionId(SessionId),
    #[error("Poisoned lock")]
    PoisonedLock,
    #[error("Failed to connect for session ID {0}: {1}")]
    Connect(SessionId, LibSshError),
    #[error("Failed to open a new channel for session ID {0}: {1}")]
    OpenChannel(SessionId, LibSshError),
    #[error("No available channel for session ID {0}")]
    NoAvailableChannel(SessionId),
    #[error("Channel unexpectedly closed for session ID {0}")]
    ChannelClosed(SessionId),
    #[error("Failed to request subsystem {2} for session ID {0}: {1}")]
    RequestSubsystem(SessionId, LibSshError, String),
    #[error("Failed to open session for session ID {0}: {1}")]
    OpenSession(SessionId, LibSshError),
    #[error("Failed to close channel for session ID {0}: {1}")]
    Close(SessionId, LibSshError),
    #[error("Error while requesting pty for session ID {0}: {1}")]
    RequestPty(SessionId, LibSshError),
    #[error("Error while requesting command execution for session ID {0}: {1}")]
    RequestExec(SessionId, LibSshError),
    #[error("Error while requesting shell for session ID {0}: {1}")]
    RequestShell(SessionId, LibSshError),
    #[error("Failed to get server public key for session ID {0}: {1} ")]
    GetServerPublicKey(SessionId, LibSshError),
    #[error("Failed to get server banner for session ID {0}: {1} ")]
    GetServerBanner(SessionId, LibSshError),
    #[error("Failed to get issue banner for session ID {0}: {1} ")]
    GetIssueBanner(SessionId, LibSshError),
    #[error("Failed to set SSH option {1:?} for session ID: {0}: {2}")]
    SetOption(SessionId, String, LibSshError),
    #[error("Failed to set authentication to keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveInfo(SessionId, LibSshError),
    #[error("Failed to initiate keyboard-interactive authentication for session ID {0}: {1} ")]
    UserAuthKeyboardInteractive(SessionId, LibSshError),
    #[error("Failed to set answers for authentication via keyboard-interactive for session ID {0}: {1} ")]
    UserAuthKeyboardInteractiveSetAnswers(SessionId, LibSshError),
    #[error("Failed to authenticate via password for session ID {0}: {1} ")]
    UserAuthPassword(SessionId, LibSshError),
    #[error("Failed to perform 'none' authentication for session ID {0}: {1} ")]
    UserAuthNone(SessionId, LibSshError),
    #[error("Failed to request list of authentication methods for session ID {0}: {1} ")]
    UserAuthList(SessionId, LibSshError),
    #[error(
        "Failed to check whether public key authentication is possible for session ID {0}: {1} "
    )]
    UserAuthTryPublicKey(SessionId, LibSshError),
    #[error("Failed to authenticate with public key for session ID {0}: {1} ")]
    UserAuthPublicKey(SessionId, LibSshError),
    #[error("Error while reading ssh for session ID {0}")]
    ReadSsh(SessionId),
    #[error("Error while initiating sftp for session ID {0}: {1}")]
    Sftp(SessionId, LibSshError),
    #[error("Failed to parse IP address '{0}' with error {1}")]
    InvalidIpAddr(String, std::net::AddrParseError),
    #[error("Attempted to authenticate without authentication data given for session ID: {0}")]
    NoAuthenticationGiven(SessionId),
}

impl From<SshError> for FunctionErrorKind {
    fn from(e: SshError) -> Self {
        FunctionErrorKind::Ssh(e)
    }
}
