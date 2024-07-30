// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines functions and structures for handling sessions

use crate::error::{Result, SshError};

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use libssh_rs::{AuthMethods, AuthStatus, InteractiveAuthInfo, Session, SshKey};
use tracing::debug;

pub type SessionId = i32;

/// Structure to hold an SSH Session
pub struct SshSession {
    /// Session ID
    pub session_id: SessionId,
    /// Ssh Session
    pub session: Session,
    /// Hold the available authentication methods
    pub authmethods: AuthMethods,
    /// Indicating that methods is valid
    pub authmethods_valid: bool,
    /// Set if a user has been set for the session
    pub user_set: bool,
    /// Channel
    pub channel: Option<Channel>,
}

impl SshSession {
    pub fn new_channel(&self) -> Result<Channel> {
        self.session
            .new_channel()
            .map(|channel| Channel {
                channel,
                session_id: self.session_id,
            })
            .map_err(|e| SshError::OpenChannel(self.session_id, e))
    }

    pub fn get_channel(&self) -> Result<&Channel> {
        self.channel
            .as_ref()
            .ok_or_else(|| SshError::NoAvailableChannel(self.session_id))
    }

    pub fn get_server_public_key(&self) -> Result<SshKey> {
        self.session
            .get_server_public_key()
            .map_err(|e| SshError::GetServerPublicKey(self.session_id, e))
    }

    pub fn get_server_banner(&self) -> Result<String> {
        self.session
            .get_server_banner()
            .map_err(|e| SshError::GetServerBanner(self.session_id, e))
    }

    pub fn get_issue_banner(&self) -> Result<String> {
        self.session
            .get_issue_banner()
            .map_err(|e| SshError::GetIssueBanner(self.session_id, e))
    }

    pub fn userauth_keyboard_interactive_info(&self) -> Result<InteractiveAuthInfo> {
        self.session
            .userauth_keyboard_interactive_info()
            .map_err(|e| SshError::UserAuthKeyboardInteractiveInfo(self.session_id, e))
    }

    pub fn userauth_keyboard_interactive(
        &self,
        name: Option<&str>,
        sub_methods: Option<&str>,
    ) -> Result<AuthStatus> {
        self.session
            .userauth_keyboard_interactive(name, sub_methods)
            .map_err(|e| SshError::UserAuthKeyboardInteractive(self.session_id, e))
    }

    pub fn userauth_keyboard_interactive_set_answers(&self, answers: &[String]) -> Result<()> {
        self.session
            .userauth_keyboard_interactive_set_answers(answers)
            .map_err(|e| SshError::UserAuthKeyboardInteractiveSetAnswers(self.session_id, e))
    }

    pub fn close(&mut self) {
        if let Some(channel) = &mut self.channel {
            if let Err(e) = channel.close() {
                debug!("Encountered error while closing channel: {}", e);
            }
        }
        self.channel = None;
    }
}

pub struct Channel {
    channel: libssh_rs::Channel,
    session_id: SessionId,
}

impl Channel {
    pub fn request_subsystem(&self, subsystem: &str) -> Result<()> {
        self.channel
            .request_subsystem(subsystem)
            .map_err(|e| SshError::RequestSubsystem(self.session_id, e, subsystem.to_string()))
    }

    pub fn open_session(&self) -> Result<()> {
        self.channel
            .open_session()
            .map_err(|e| SshError::OpenSession(self.session_id, e))
    }

    pub fn channel_mut(&mut self) -> &mut libssh_rs::Channel {
        &mut self.channel
    }

    pub fn is_closed(&self) -> bool {
        self.channel.is_closed()
    }

    pub fn close(&self) -> Result<()> {
        self.channel
            .close()
            .map_err(|e| SshError::Close(self.session_id, e))
    }

    pub fn stdin(&self) -> impl std::io::Write + '_ {
        self.channel.stdin()
    }

    pub fn ensure_open(&self) -> Result<()> {
        if self.is_closed() {
            Err(SshError::ChannelClosed(self.session_id))
        } else {
            Ok(())
        }
    }

    fn buf_as_str<'a>(&self, buf: &'a [u8]) -> Result<&'a str> {
        std::str::from_utf8(buf).map_err(|_| SshError::ReadSsh(self.session_id))
    }

    fn read_timeout(&self, timeout: Duration, stderr: bool) -> Result<String> {
        let mut buf: [u8; 4096] = [0; 4096];
        let mut response = String::new();
        loop {
            match self.channel.read_timeout(&mut buf, stderr, Some(timeout)) {
                Ok(0) => break,
                Ok(num_bytes) => {
                    response.push_str(self.buf_as_str(&buf[..num_bytes])?);
                }
                Err(libssh_rs::Error::TryAgain) => {}
                Err(_) => {
                    return Err(SshError::ReadSsh(self.session_id));
                }
            }
        }
        Ok(response)
    }

    pub fn read_ssh_blocking(&self, timeout: Duration) -> Result<String> {
        let stderr = self.read_timeout(timeout, true)?;
        let stdout = self.read_timeout(timeout, false)?;
        Ok(format!("{}{}", stderr, stdout))
    }

    fn read_nonblocking(&self, stderr: bool) -> Result<String> {
        let mut buf: [u8; 4096] = [0; 4096];
        match self.channel.read_nonblocking(&mut buf, stderr) {
            Ok(n) => {
                let response = self.buf_as_str(&buf[..n])?.to_string();
                Ok(response)
            }
            Err(_) => {
                return Err(SshError::ReadSsh(self.session_id));
            }
        }
    }

    pub fn read_ssh_nonblocking(&self) -> Result<String> {
        if self.channel.is_closed() || self.channel.is_eof() {
            return Err(SshError::ReadSsh(self.session_id));
        }

        let stderr = self.read_nonblocking(true)?;
        let stdout = self.read_nonblocking(true)?;
        Ok(format!("{}{}", stderr, stdout))
    }
}

pub struct Sessions {
    sessions: Vec<(SessionId, Arc<Mutex<SshSession>>)>,
}

impl Sessions {
    pub fn get_by_id(&self, id: SessionId) -> Result<MutexGuard<SshSession>> {
        let (_, session) = self
            .sessions
            .iter()
            .find(|(session_id, _)| *session_id == id)
            .ok_or_else(|| SshError::InvalidSessionId(id))?;
        session.lock().map_err(|_| SshError::PoisonedLock)
    }
}
