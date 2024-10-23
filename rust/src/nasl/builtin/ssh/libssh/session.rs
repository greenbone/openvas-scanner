use libssh_rs::{AuthMethods, AuthStatus, InteractiveAuthInfo, Session, Sftp, SshKey, SshOption};
use std::sync::MutexGuard;
use std::{os::fd::AsRawFd, time::Duration};
use tracing::{debug, info};

use crate::nasl::builtin::ssh::SessionId;

use super::super::error::{Result, SshError};
use super::{channel::Channel, Socket};

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
    pub channel: Option<Channel>,
}

impl SshSession {
    pub fn new(id: SessionId) -> Result<Self> {
        Session::new()
            .map_err(|e| SshError::NewSession(e))
            .map(|session| Self {
                session,
                id,
                authmethods: None,
                user_set: false,
                channel: None,
            })
    }
}

pub struct BorrowedSession<'a> {
    guard: MutexGuard<'a, SshSession>,
}

impl<'a> BorrowedSession<'a> {
    pub fn new(guard: MutexGuard<'a, SshSession>) -> Self {
        Self { guard }
    }

    fn borrow(&self) -> &SshSession {
        &self.guard
    }

    fn borrow_mut(&mut self) -> &mut SshSession {
        &mut self.guard
    }

    fn session(&self) -> &Session {
        &self.borrow().session
    }

    pub fn id(&self) -> SessionId {
        self.borrow().id
    }

    fn channel(&self) -> &Option<Channel> {
        &self.borrow().channel
    }

    pub fn set_channel(&mut self, channel: Channel) {
        self.borrow_mut().channel = Some(channel);
    }

    fn authmethods(&self) -> Option<AuthMethods> {
        self.borrow().authmethods
    }

    fn user_set(&self) -> bool {
        self.borrow().user_set
    }

    pub fn new_channel(&self) -> Result<Channel> {
        self.session()
            .new_channel()
            .map(|channel| Channel::new(channel, self.id()))
            .map_err(|e| SshError::OpenChannel(self.id(), e))
    }

    pub fn get_channel(&self) -> Result<&Channel> {
        self.channel()
            .as_ref()
            .ok_or_else(|| SshError::NoAvailableChannel(self.id()))
    }

    pub fn get_authmethods_cached(&mut self) -> Result<AuthMethods> {
        if let Some(authmethods) = self.authmethods() {
            Ok(authmethods)
        } else {
            self.get_authmethods()
        }
    }

    pub fn set_option(&self, option: SshOption) -> Result<()> {
        let formatted = format!("{:?}", option);
        self.session()
            .set_option(option)
            .map_err(|e| SshError::SetOption(self.id(), formatted, e))
    }

    pub fn get_socket(&self) -> Socket {
        self.session().as_raw_fd()
    }

    pub fn close(&mut self) {
        if let Some(channel) = &mut self.channel() {
            if let Err(e) = channel.close() {
                debug!("Encountered error while closing channel: {}", e);
            }
        }
        self.borrow_mut().channel = None;
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

    pub fn open_shell(&mut self, pty: bool) -> Result<()> {
        let mut channel = self.new_channel()?;
        channel.open_session()?;
        self.request_ssh_shell(&mut channel, pty)?;
        self.borrow_mut().channel = Some(channel);
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<()> {
        if let Some(ref channel) = self.borrow_mut().channel {
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

    pub fn exec_ssh_cmd(
        &self,
        cmd: &str,
        compat_mode: bool,
        to_stdout: bool,
        to_stderr: bool,
    ) -> Result<String> {
        let channel = self.new_channel()?;
        channel.open_session()?;
        channel.request_pty("xterm", 80, 24)?;
        channel.request_exec(cmd)?;

        let mut response = String::new();

        let timeout = Duration::from_millis(15000);
        let stderr = channel.read_timeout(timeout, true)?;
        if to_stderr {
            response.push_str(stderr.as_str());
        }
        let stdout = channel.read_timeout(timeout, false)?;
        if to_stdout {
            response.push_str(stdout.as_str());
        }
        if compat_mode {
            response.push_str(&stderr.as_str())
        }
        Ok(response)
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
        self.borrow_mut().authmethods = Some(authmethods);
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
            self.session()
                .$name($($arg),*)
                .map_err(|e| SshError::$err_variant(self.id(), e))
        }
    }
}

impl<'a> BorrowedSession<'a> {
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
    inherit_method!(userauth_try_publickey, AuthStatus, UserAuthTryPublicKey, username: Option<&str>, key: &SshKey);
    inherit_method!(userauth_publickey, AuthStatus, UserAuthPublicKey, username: Option<&str>, key: &SshKey);
    inherit_method!(
        userauth_keyboard_interactive_info,
        InteractiveAuthInfo,
        UserAuthKeyboardInteractiveInfo
    );
}
