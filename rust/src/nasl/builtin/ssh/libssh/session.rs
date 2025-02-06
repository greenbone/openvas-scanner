// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use libssh_rs::{AuthMethods, AuthStatus, InteractiveAuthInfo, Session, Sftp, SshKey, SshOption};
use std::{os::fd::AsRawFd, time::Duration};
use tokio::sync::{Mutex, MutexGuard};
use tracing::{debug, info};

use super::super::error::{Result, SshErrorKind};
use super::super::Output;
use super::SessionId;
use super::{channel::Channel, Socket};
use crate::nasl::utils::error::WithErrorInfo;

/// Structure to hold an SSH Session
pub struct SshSession {
    /// Session ID
    pub id: SessionId,
    /// Ssh Session
    pub session: Session,
    /// Hold the available authentication methods
    pub authmethods: Option<AuthMethods>,
    /// Set if a user has been set for the session
    pub user_set: bool,
    /// Channel
    pub channel: Option<Mutex<Channel>>,
}

impl SshSession {
    pub fn new(id: SessionId) -> Result<Self> {
        Session::new()
            .map_err(|e| SshErrorKind::NewSession.with(e))
            .map(|session| Self {
                session,
                id,
                authmethods: None,
                user_set: false,
                channel: None,
            })
    }
}

impl SshSession {
    fn session(&self) -> &Session {
        &self.session
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    async fn channel(&self) -> Option<MutexGuard<'_, Channel>> {
        if let Some(ref channel) = self.channel {
            Some(channel.lock().await)
        } else {
            None
        }
    }

    pub fn set_channel(&mut self, channel: Channel) {
        self.channel = Some(Mutex::new(channel));
    }

    fn authmethods(&self) -> Option<AuthMethods> {
        self.authmethods
    }

    fn user_set(&self) -> bool {
        self.user_set
    }

    pub fn new_channel(&self) -> Result<Channel> {
        self.session()
            .new_channel()
            .map(|channel| Channel::new(channel, self.id()))
            .map_err(|e| SshErrorKind::OpenChannel.with(self.id()).with(e))
    }

    pub async fn get_channel(&self) -> Result<MutexGuard<'_, Channel>> {
        self.channel()
            .await
            .ok_or_else(|| SshErrorKind::NoAvailableChannel.with(self.id()))
    }

    pub fn get_authmethods_cached(&mut self) -> Result<AuthMethods> {
        if let Some(authmethods) = self.authmethods() {
            Ok(authmethods)
        } else {
            self.get_authmethods()
        }
    }

    pub fn set_option(&self, option: SshOption) -> Result<()> {
        // We have to format this before we set it, even if we might
        // not need it, since SshOption does implement Clone
        let formatted = format!("{:?}", option);
        self.session()
            .set_option(option)
            .map_err(|e| SshErrorKind::SetOption(formatted).with(self.id()).with(e))
    }

    pub fn get_socket(&self) -> Socket {
        self.session().as_raw_fd()
    }

    pub async fn close(&mut self) {
        if let Some(channel) = &mut self.channel().await {
            if let Err(e) = channel.close() {
                debug!("Encountered error while closing channel: {}", e);
            }
        }
        self.channel = None;
    }

    pub fn ensure_user_set(&mut self, login: Option<&str>) -> Result<()> {
        if !self.user_set() {
            self.set_opt_user(login)
        } else {
            Ok(())
        }
    }

    pub fn set_opt_user(&mut self, login: Option<&str>) -> Result<()> {
        // TODO: get the username alternatively from the kb.
        let opt_user = SshOption::User(login.map(|x| x.to_string()));
        self.set_option(opt_user)
    }

    pub async fn open_shell(&mut self, pty: bool) -> Result<()> {
        let mut channel = self.new_channel()?;
        channel.open_session()?;
        self.request_ssh_shell(&mut channel, pty)?;
        self.set_channel(channel);
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(ref channel) = self.channel().await {
            channel.close()?;
        }
        self.session().disconnect();
        Ok(())
    }

    /// Request and set a shell. It set the pty if necessary.
    fn request_ssh_shell(&self, channel: &mut Channel, pty: bool) -> Result<()> {
        if pty {
            channel.request_pty("xterm", 80, 24)
        } else {
            channel.request_shell()
        }
    }

    pub async fn exec_ssh_cmd(&self, cmd: &str) -> Result<Output> {
        let channel = self.new_channel()?;
        channel.open_session()?;
        channel.request_pty("xterm", 80, 24)?;
        channel.request_exec(cmd)?;

        let timeout = Duration::from_millis(15000);
        let stderr = channel.read_timeout(timeout, true)?;
        let stdout = channel.read_timeout(timeout, false)?;
        Ok(Output { stdout, stderr })
    }

    pub async fn auth_method_allowed(&mut self, method: AuthMethods) -> Result<bool> {
        let methods = self.get_authmethods_cached()?;
        Ok(methods.contains(method))
    }

    pub async fn auth_password(&mut self, login: &str, password: &str) -> Result<()> {
        self.ensure_user_set(Some(login))?;
        let status = self.userauth_password(None, Some(password))?;
        if let AuthStatus::Success = status {
            return Ok(());
        }
        Err(SshErrorKind::UserAuthPassword.with(self.id))
    }

    pub async fn auth_keyboard_interactive(&mut self, login: &str, password: &str) -> Result<()> {
        self.ensure_user_set(Some(login))?;
        loop {
            let response = self.userauth_keyboard_interactive(None, None)?;
            if let AuthStatus::Info = response {
                let info = self.userauth_keyboard_interactive_info()?;
                let mut answers: Vec<String> = Vec::new();
                for p in info.prompts.into_iter() {
                    if !p.echo {
                        answers.push(password.to_string());
                    } else {
                        answers.push(String::new());
                    };
                }
                match self.userauth_keyboard_interactive_set_answers(&answers) {
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(_) => return Err(SshErrorKind::UserAuthKeyboardInteractive.with(self.id)),
                }
            } else {
                debug!(
                    session_id = self.id,
                    "SSH keyboard-interactive authentication failed.",
                );
                continue;
            }
        }
    }

    fn get_authmethods(&mut self) -> Result<AuthMethods> {
        let authmethods = match self.userauth_none(None)? {
            AuthStatus::Success => {
                info!("SSH authentication succeeded using the none method - should not happen; very old server?");
                AuthMethods::NONE
            }
            _ => {
                match self.userauth_list(None) {
                    Ok(list) => list,
                    Err(_) => {
                        debug!("SSH server did not return a list of authentication methods - trying all");
                        AuthMethods::HOST_BASED
                            | AuthMethods::INTERACTIVE
                            | AuthMethods::NONE
                            | AuthMethods::PASSWORD
                            | AuthMethods::PUBLIC_KEY
                    }
                }
            }
        };
        self.authmethods = Some(authmethods);
        Ok(authmethods)
    }
}

/// Conveniene macro to implement a method of the underlying
/// libssh::Session by calling it with all given arguments and
/// transforming the Err variant according to the given SshError
/// variant, giving it the session id and the error message.
macro_rules! inherit_method {
    ($name: ident, $ret: ty, $err_variant: ident $(,)? $($arg: ident : $argtype: ty),*) => {
        pub fn $name(&self, $($arg: $argtype),*) -> Result<$ret> {
            self.session.$name($($arg),*)
                .map_err(|e| SshErrorKind::$err_variant.with(self.id()).with(e))
        }
    }
}

impl SshSession {
    inherit_method!(connect, (), Connect);
    inherit_method!(get_server_public_key, SshKey, GetServerPublicKey);
    inherit_method!(get_server_banner, String, GetServerBanner);
    inherit_method!(get_issue_banner, String, GetIssueBanner);
    inherit_method!(sftp, Sftp, Sftp);
    inherit_method!(userauth_keyboard_interactive, AuthStatus, UserAuthKeyboardInteractive, name: Option<&str>, sub_methods: Option<&str>);
    inherit_method!(userauth_keyboard_interactive_set_answers, (), UserAuthKeyboardInteractiveSetAnswers, answers: &[String]);
    inherit_method!(userauth_password, AuthStatus, UserAuthPassword, username: Option<&str>, password: Option<&str>);
    inherit_method!(userauth_none, AuthStatus, UserAuthNone, username: Option<&str>);
    inherit_method!(userauth_list, AuthMethods, UserAuthList, username: Option<&str>);
    inherit_method!(
        userauth_keyboard_interactive_info,
        InteractiveAuthInfo,
        UserAuthKeyboardInteractiveInfo
    );
}
