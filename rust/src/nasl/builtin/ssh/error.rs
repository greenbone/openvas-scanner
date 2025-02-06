// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt;

use thiserror::Error;

use crate::nasl::utils::error::WithErrorInfo;

use super::SessionId;

/// A cloneable representation of the Error type of the underlying SSH lib
#[derive(Clone, Debug, Error)]
#[error("{0}")]
pub struct LibError(String);

#[cfg(feature = "nasl-builtin-libssh")]
impl From<libssh_rs::Error> for LibError {
    fn from(e: libssh_rs::Error) -> Self {
        Self(format!("{}", e))
    }
}

#[cfg(not(feature = "nasl-builtin-libssh"))]
impl From<russh::Error> for LibError {
    fn from(e: russh::Error) -> Self {
        Self(format!("{}", e))
    }
}

#[derive(Debug, Error)]
pub struct SshError {
    pub kind: SshErrorKind,
    id: Option<SessionId>,
    #[source]
    source: Option<LibError>,
}

pub type Result<T> = std::result::Result<T, SshError>;

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(id) = self.id {
            write!(f, " Session ID: {0}.", id)?;
        }
        if let Some(ref source) = self.source {
            write!(f, " {}", source)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error)]
pub enum SshErrorKind {
    #[error("Failed to open new SSH session.")]
    NewSession,
    #[error("Invalid SSH session ID.")]
    InvalidSessionId,
    #[error("Poisoned lock.")]
    PoisonedLock,
    #[error("Failed to connect.")]
    Connect,
    #[error("Failed to open a new channel.")]
    OpenChannel,
    #[error("No available channel.")]
    NoAvailableChannel,
    #[error("Channel unexpectedly closed.")]
    ChannelClosed,
    #[error("Failed to request subsystem {0}.")]
    RequestSubsystem(String),
    #[error("Failed to open session.")]
    OpenSession,
    #[error("Failed to close channel.")]
    Close,
    #[error("Failed to request PTY.")]
    RequestPty,
    #[error("Failed to request command execution.")]
    RequestExec(String),
    #[error("Failed to request shell.")]
    RequestShell,
    #[error("Failed to get server public key.")]
    GetServerPublicKey,
    #[error("Failed to get server banner.")]
    GetServerBanner,
    #[error("Failed to get issue banner.")]
    GetIssueBanner,
    #[error("Failed to set SSH option {0}.")]
    SetOption(String),
    #[error("Failed to set authentication to keyboard-interactive.")]
    UserAuthKeyboardInteractiveInfo,
    #[error("Failed to initiate keyboard-interactive authentication.")]
    UserAuthKeyboardInteractive,
    #[error("Failed to set answers for authentication via keyboard-interactive.")]
    UserAuthKeyboardInteractiveSetAnswers,
    #[error("Failed to authenticate via password.")]
    UserAuthPassword,
    #[error("Failed to perform 'none' authentication.")]
    UserAuthNone,
    #[error("Failed to request list of authentication methods.")]
    UserAuthList,
    #[error("Failed to check whether public key authentication is possible")]
    UserAuthTryPublicKey,
    #[error("Failed to authenticate with public key.")]
    UserAuthPublicKey,
    #[error("Failed to read.")]
    ReadSsh,
    #[error("Error initiating SFTP.")]
    Sftp,
    #[error("Failed to parse IP address '{0}' with error {1}.")]
    InvalidIpAddr(String, std::net::AddrParseError),
    #[error("Attempted to authenticate without authentication data.")]
    NoAuthenticationGiven,
    #[error("Error while converting private key")]
    ConvertPrivateKey,
    #[error("Not yet implemented.")]
    Unimplemented,
    #[error("Unexpected authentication status")]
    UnexpectedAuthenticationStatus(String),
}

impl WithErrorInfo<SessionId> for SshError {
    type Error = SshError;

    fn with(mut self, id: SessionId) -> SshError {
        self.id = Some(id);
        self
    }
}

#[cfg(feature = "nasl-builtin-libssh")]
impl WithErrorInfo<libssh_rs::Error> for SshError {
    type Error = SshError;

    fn with(mut self, source: libssh_rs::Error) -> SshError {
        self.source = Some(source.into());
        self
    }
}

#[cfg(not(feature = "nasl-builtin-libssh"))]
impl WithErrorInfo<russh::Error> for SshError {
    type Error = SshError;

    fn with(mut self, source: russh::Error) -> SshError {
        self.source = Some(source.into());
        self
    }
}

impl From<SshErrorKind> for SshError {
    fn from(kind: SshErrorKind) -> Self {
        SshError {
            kind,
            source: None,
            id: None,
        }
    }
}

impl SshErrorKind {
    pub fn with<Info>(self, m: Info) -> <SshError as WithErrorInfo<Info>>::Error
    where
        SshError: WithErrorInfo<Info>,
    {
        let e: SshError = self.into();
        e.with(m)
    }
}
