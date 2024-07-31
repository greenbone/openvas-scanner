use libssh_rs::{AuthMethods, AuthStatus, InteractiveAuthInfo, Session, SshKey, SshOption};
use std::sync::MutexGuard;
use std::{os::fd::AsRawFd, time::Duration};
use tracing::{debug, info};

use super::{channel::Channel, sessions::SessionId, Socket};

use crate::error::{Result, SshError};

/// Structure to hold an SSH Session
pub struct SshSession {
    /// Session ID
    pub id: SessionId,
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
    pub fn new(id: SessionId) -> Result<Self> {
        Session::new()
            .map_err(|e| SshError::NewSession(e))
            .map(|session| Self {
                session,
                id,
                authmethods: AuthMethods::NONE,
                authmethods_valid: false,
                user_set: false,
                channel: None,
            })
    }
}

pub struct BorrowedSession<'a> {
    guard: MutexGuard<'a, Vec<SshSession>>,
    index: usize,
}

impl<'a> BorrowedSession<'a> {
    pub fn new(guard: MutexGuard<'a, Vec<SshSession>>, id: SessionId) -> Result<Self> {
        let index = guard
            .iter()
            .enumerate()
            .find(|(_, session)| session.id == id)
            .ok_or_else(|| SshError::InvalidSessionId(id))?
            .0;
        Ok(Self { guard, index })
    }

    pub fn from_index(guard: MutexGuard<'a, Vec<SshSession>>, index: usize) -> Self {
        Self { guard, index }
    }

    pub fn take_guard(self) -> MutexGuard<'a, Vec<SshSession>> {
        self.guard
    }

    fn borrow(&self) -> &SshSession {
        &self.guard[self.index]
    }

    // TODO: Make this private
    pub fn borrow_mut(&mut self) -> &mut SshSession {
        &mut self.guard[self.index]
    }

    // TODO: Make this private
    pub fn session(&self) -> &Session {
        &self.borrow().session
    }

    pub fn id(&self) -> SessionId {
        self.borrow().id
    }

    fn channel(&self) -> &Option<Channel> {
        &self.borrow().channel
    }

    fn authmethods_valid(&self) -> bool {
        self.borrow().authmethods_valid
    }

    fn authmethods(&self) -> AuthMethods {
        self.borrow().authmethods
    }

    fn user_set(&self) -> bool {
        self.borrow().user_set
    }
}

impl<'a> BorrowedSession<'a> {
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

    pub fn get_server_public_key(&self) -> Result<SshKey> {
        self.session()
            .get_server_public_key()
            .map_err(|e| SshError::GetServerPublicKey(self.id(), e))
    }

    pub fn get_server_banner(&self) -> Result<String> {
        self.session()
            .get_server_banner()
            .map_err(|e| SshError::GetServerBanner(self.id(), e))
    }

    pub fn get_issue_banner(&self) -> Result<String> {
        self.session()
            .get_issue_banner()
            .map_err(|e| SshError::GetIssueBanner(self.id(), e))
    }

    pub fn get_authmethods_cached(&mut self) -> Result<AuthMethods> {
        if !self.authmethods_valid() {
            self.get_authmethods()
        } else {
            Ok(self.authmethods())
        }
    }

    pub fn get_socket(&self) -> Socket {
        self.session().as_raw_fd()
    }

    pub fn userauth_keyboard_interactive(
        &self,
        name: Option<&str>,
        sub_methods: Option<&str>,
    ) -> Result<AuthStatus> {
        self.session()
            .userauth_keyboard_interactive(name, sub_methods)
            .map_err(|e| SshError::UserAuthKeyboardInteractive(self.id(), e))
    }

    pub fn userauth_keyboard_interactive_info(&self) -> Result<InteractiveAuthInfo> {
        self.session()
            .userauth_keyboard_interactive_info()
            .map_err(|e| SshError::UserAuthKeyboardInteractiveInfo(self.id(), e))
    }

    pub fn userauth_keyboard_interactive_set_answers(&self, answers: &[String]) -> Result<()> {
        self.session()
            .userauth_keyboard_interactive_set_answers(answers)
            .map_err(|e| SshError::UserAuthKeyboardInteractiveSetAnswers(self.id(), e))
    }

    pub fn userauth_password(
        &self,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<AuthStatus> {
        self.session()
            .userauth_password(username, password)
            .map_err(|e| SshError::UserAuthPassword(self.id(), e))
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

    pub fn set_option(&mut self, option: SshOption) -> Result<()> {
        let option_str = format!("{:?}", option);
        self.session()
            .set_option(option)
            .map_err(|e| SshError::SetOption(self.id(), option_str, e))
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

    fn userauth_none(&self, username: Option<&str>) -> Result<AuthStatus> {
        self.session()
            .userauth_none(username)
            .map_err(|e| SshError::UserAuthNone(self.id(), e))
    }

    fn userauth_list(&self, username: Option<&str>) -> Result<AuthMethods> {
        self.session()
            .userauth_list(username)
            .map_err(|e| SshError::UserAuthList(self.id(), e))
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
        self.borrow_mut().authmethods = authmethods;
        self.borrow_mut().authmethods_valid = true;
        Ok(authmethods)
    }
}
