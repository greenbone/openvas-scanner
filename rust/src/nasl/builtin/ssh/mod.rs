// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod error;
mod sessions;
mod utils;

#[cfg(feature = "nasl-builtin-libssh")]
mod libssh;
#[cfg(feature = "nasl-builtin-libssh")]
pub use libssh::{AuthMethods, SessionId, Socket, SshSession};

#[cfg(not(feature = "nasl-builtin-libssh"))]
mod russh;
#[cfg(not(feature = "nasl-builtin-libssh"))]
pub use russh::{AuthMethods, SessionId, Socket, SshSession};

#[cfg(test)]
mod tests;

pub use error::SshError;
pub use sessions::SshSessions as Ssh;

use std::time::Duration;

use ::russh::{cipher, Preferred};
use russh_keys::key;

use crate::nasl::prelude::*;

use error::SshErrorKind;
use utils::CommaSeparated;

#[cfg(feature = "nasl-builtin-libssh")]
mod libssh_uses {
    pub use crate::nasl::utils::function::{Maybe, StringOrData};
    pub use libssh_rs::{AuthStatus, PublicKeyHashType};
    pub use std::io::Write;
    pub use tracing::debug;
}

#[cfg(feature = "nasl-builtin-libssh")]
pub use libssh_uses::*;

type Result<T> = std::result::Result<T, FnError>;

const DEFAULT_SSH_PORT: u16 = 22;

pub struct Output {
    stdout: String,
    stderr: String,
}

impl Output {
    fn combine(&self, to_stdout: bool, to_stderr: bool, compat_mode: bool) -> String {
        let mut response = String::new();
        if to_stderr {
            response.push_str(self.stderr.as_str());
        }
        if to_stdout {
            response.push_str(self.stdout.as_str());
        }
        if compat_mode {
            response.push_str(self.stderr.as_str())
        }
        response
    }
}

#[cfg(feature = "nasl-builtin-libssh")]
function_set! {
    Ssh,
    (
        (Ssh::nasl_ssh_connect, "ssh_connect"),
        (Ssh::nasl_ssh_request_exec, "ssh_request_exec"),
        (Ssh::nasl_ssh_userauth, "ssh_userauth"),
        (Ssh::nasl_ssh_disconnect, "ssh_disconnect"),
        (Ssh::nasl_ssh_session_id_from_sock, "ssh_session_id_from_sock"),
        (Ssh::nasl_ssh_get_sock, "ssh_get_sock"),
        (Ssh::nasl_ssh_set_login, "ssh_set_login"),
        (Ssh::nasl_ssh_shell_open, "ssh_shell_open"),
        (Ssh::nasl_ssh_shell_read, "ssh_shell_read"),
        (Ssh::nasl_ssh_shell_write, "ssh_shell_write"),
        (Ssh::nasl_ssh_shell_close, "ssh_shell_close"),
        (Ssh::nasl_ssh_login_interactive, "ssh_login_interactive"),
        (Ssh::nasl_ssh_login_interactive_pass, "ssh_login_interactive_pass"),
        (Ssh::nasl_ssh_get_issue_banner, "ssh_get_issue_banner"),
        (Ssh::nasl_ssh_get_server_banner, "ssh_get_server_banner"),
        (Ssh::nasl_ssh_get_auth_methods, "ssh_get_auth_methods"),
        (Ssh::nasl_ssh_get_host_key, "ssh_get_host_key"),
        (Ssh::nasl_sftp_enabled_check, "sftp_enabled_check"),
        (Ssh::nasl_ssh_execute_netconf_subsystem, "ssh_execute_netconf_subsystem"),
    )
}

#[cfg(not(feature = "nasl-builtin-libssh"))]
function_set! {
    Ssh,
    (
        (Ssh::nasl_ssh_connect, "ssh_connect"),
        (Ssh::nasl_ssh_request_exec, "ssh_request_exec"),
        (Ssh::nasl_ssh_userauth, "ssh_userauth"),
        (Ssh::nasl_ssh_disconnect, "ssh_disconnect"),
    )
}

impl Ssh {
    /// Connect to the target host via TCP and setup an ssh
    ///        connection.
    ///
    /// If the named argument "socket" is given, that socket will be used
    /// instead of a creating a new TCP connection.  If socket is not given
    /// or 0, the port is looked up in the preferences and the KB unless
    /// overridden by the named parameter "port".
    ///
    /// On success an ssh session to the host has been established; the
    /// caller may then run an authentication function.  If the connection
    /// is no longer needed, ssh_disconnect may be used to disconnect and
    /// close the socket.
    ///
    /// nasl named params:
    ///
    /// - socket If given, this socket will be used instead of creating
    ///          a new connection.
    ///
    /// - port A non-standard port to connect to.  This is only used if
    ///        socket is not given or 0.
    ///
    /// - keytype List of the preferred server host key types. Example:
    ///           "ssh-rsa,ssh-dss"
    ///
    /// - csciphers SSH client-to-server ciphers.
    ///
    /// - scciphers SSH server-to-client ciphers.
    ///
    /// - timeout Set a timeout for the connection in seconds. Defaults to 10
    /// seconds (defined by libssh internally) if not given.
    ///
    /// nasl return An integer to identify the ssh session. Zero on error.
    #[nasl_function(named(socket, port, keytype, csciphers, scciphers, timeout))]
    pub async fn nasl_ssh_connect(
        &mut self,
        ctx: &Context<'_>,
        socket: Option<Socket>,
        port: Option<u16>,
        keytype: Option<CommaSeparated<key::Name>>,
        csciphers: Option<CommaSeparated<cipher::Name>>,
        scciphers: Option<CommaSeparated<cipher::Name>>,
        timeout: Option<u64>,
    ) -> Result<SessionId> {
        let port = port
            .filter(|_| socket.is_none())
            .unwrap_or(DEFAULT_SSH_PORT);
        let ip = ctx.target_ip();
        let timeout = timeout.map(Duration::from_secs);
        let keytype = keytype
            .map(|keytype| keytype.0)
            .unwrap_or(Preferred::DEFAULT.key[..].to_vec());
        let csciphers = csciphers
            .map(|cscipher| cscipher.0)
            .unwrap_or(Preferred::DEFAULT.cipher[..].to_vec());
        let scciphers = scciphers
            .map(|sccipher| sccipher.0)
            .unwrap_or(Preferred::DEFAULT.cipher[..].to_vec());

        Ok(self
            .connect(socket, ip, port, keytype, csciphers, scciphers, timeout)
            .await?)
    }

    /// Run a command via ssh.
    ///
    /// The function opens a channel to the remote end and ask it to
    /// execute a command.  The output of the command is then returned as a
    /// data block.  The first unnamed argument is the session id. The
    /// command itself is expected as string in the named argument "cmd".
    ///
    /// Regarding the handling of the stderr and stdout stream, this
    /// function may be used in different modes.
    ///
    /// If either the named arguments @a stdout or @a stderr are given and
    /// that one is set to 1, only the output of the specified stream is
    /// returned.
    ///
    /// If stdout and stderr are both given and set to 1, the output
    /// of both is returned interleaved.  NOTE: The following feature has
    /// not yet been implemented: The output is guaranteed not to switch
    /// between stderr and stdout within a line.
    ///
    /// If stdout and stderr are both given but set to 0, a special
    /// backward compatibility mode is used: First all output to stderr is
    /// collected up until any output to stdout is received.  Then all
    /// output to stdout is returned while ignoring all further stderr
    /// output; at EOF the initial collected data from stderr is returned.
    ///
    /// If the named parameters @a stdout and @a stderr are not given, the
    /// function acts exactly as if only @a stdout has been set to 1.
    #[nasl_function(named(cmd, stdout, stderr))]
    pub async fn nasl_ssh_request_exec(
        &self,
        session_id: SessionId,
        cmd: &str,
        stdout: Option<bool>,
        stderr: Option<bool>,
    ) -> Result<Option<String>> {
        let session = self.get_by_id(session_id).await?;
        if cmd.is_empty() {
            return Ok(None);
        }
        let (to_stdout, to_stderr, compat_mode) = match (stdout, stderr) {
            (None, None) => (true, false, false),
            (Some(false), Some(false)) => (true, false, true),
            (stdout, stderr) => (stdout.unwrap_or(false), stderr.unwrap_or(false), false),
        };
        // TODO: Currently the compat mode above is not implemented as described
        // but instead we receive stderr and stdout until EOF and then combine the two.
        Ok(Some(session.exec_ssh_cmd(cmd).await?.combine(
            to_stdout,
            to_stderr,
            compat_mode,
        )))
    }

    /// Authenticate a user on an ssh connection
    ///
    /// The function expects the session id as its first unnamed argument.
    /// The first time this function is called for a session id, the named
    /// argument "login" is also expected; it defaults the KB entry
    /// "Secret/SSH/login".  It should contain the user name to login.
    /// Given that many servers don't allow changing the login for an
    /// established connection, the "login" parameter is silently ignored
    /// on all further calls.
    ///
    /// To perform a password based authentication, the named argument
    /// "password" must contain a password.
    ///
    /// To perform a public key based authentication, the named argument
    /// "privatekey" must contain a base64 encoded private key in ssh
    /// native or in PKCS#8 format.
    ///
    /// If both, "password" and "privatekey" are given as named arguments
    /// only "password" is used.  If neither are given the values are taken
    /// from the KB ("Secret/SSH/password" and "Secret/SSH/privatekey") and
    /// tried in the order {password, privatekey}.  Note well, that if one
    /// of the named arguments are given, only those are used and the KB is
    /// not consulted.
    ///
    /// If the private key is protected, its passphrase is taken from the
    /// named argument "passphrase" or, if not given, taken from the KB
    /// ("Secret/SSH/passphrase").
    ///
    /// Note that the named argument "publickey" and the KB item
    /// ("Secret/SSH/publickey") are ignored - they are not longer required
    /// because they can be derived from the private key.
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// nasl named params
    ///
    /// - login: A string with the login name.
    ///
    /// - password: A string with the password.
    ///
    /// - privatekey: A base64 encoded private key in ssh native or in
    ///   pkcs#8 format.  This parameter is ignored if password is given.
    ///
    /// - passphrase: A string with the passphrase used to unprotect privatekey.
    ///
    /// return An integer as status value; 0 indicates success.
    #[nasl_function(named(login, password, privatekey, passphrase))]
    pub async fn nasl_ssh_userauth(
        &self,
        session_id: SessionId,
        login: Option<&str>,
        password: Option<&str>,
        privatekey: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<()> {
        if password.is_none() && privatekey.is_none() && passphrase.is_none() {
            //TODO: Get values from KB
            return Err(SshErrorKind::NoAuthenticationGiven.with(session_id).into());
        }
        let login = login.unwrap_or("");
        let mut session = self.get_by_id(session_id).await?;
        // Check whether a password has been given.  If so, try to
        // authenticate using that password.  Note that the OpenSSH client
        // uses a different order: it first tries the public key and then the
        // password.  However, the old NASL SSH protocol implementation tries
        // the password before the public key authentication.  Because we
        // want to be compatible, we do it in that order.
        if let Some(password) = password {
            if session.auth_method_allowed(AuthMethods::PASSWORD).await?
                && session.auth_password(login, password).await.is_ok()
            {
                return Ok(());
            }
            if session
                .auth_method_allowed(AuthMethods::INTERACTIVE)
                .await?
                && session
                    .auth_keyboard_interactive(login, password)
                    .await
                    .is_ok()
            {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Disconnect an ssh connection
    /// This function takes the ssh session id (as returned by ssh_connect)
    /// as its only unnamed argument.  Passing 0 as session id is
    /// explicitly allowed and does nothing.  If there are any open
    /// channels they are closed as well and their ids will be marked as
    /// invalid.
    #[nasl_function]
    pub async fn nasl_ssh_disconnect(&mut self, session_id: SessionId) -> Result<()> {
        if session_id != 0 {
            self.disconnect_and_remove(session_id).await?;
        }
        Ok(())
    }
}

#[cfg(feature = "nasl-builtin-libssh")]
impl Ssh {
    /// Given a socket, return the corresponding session id if available.
    #[nasl_function]
    pub async fn nasl_ssh_session_id_from_sock(&self, socket: Socket) -> Result<Option<SessionId>> {
        Ok(self
            .find_id(|session| session.get_socket() == socket)
            .await?)
    }

    /// Given a session id, return the corresponding socket
    /// The socket is either a native file descriptor or a NASL connection
    /// socket (if a open socket was passed to ssh_connect).  The NASL
    /// network code handles both of them.
    ///
    /// nasl params
    /// - An SSH session id.
    ///
    /// return An integer representing the socket or -1 on error.
    #[nasl_function]
    pub async fn nasl_ssh_get_sock(&self, session_id: SessionId) -> Result<Socket> {
        let session = self.get_by_id(session_id).await?;
        Ok(session.get_socket())
    }
    /// Set the login name for the authentication.
    ///
    /// This is an optional function and usually not required.  However,
    /// if you want to get the banner before starting the authentication,
    /// you need to tell libssh the user because it is often not possible
    /// to change the user after the first call to an authentication
    /// methods - getting the banner uses an authentication function.
    ///
    /// The named argument "login" is used for the login name; it defaults
    /// to the KB entry "Secret/SSH/login".  It should contain the user name
    /// to login.  Given that many servers don't allow changing the login
    /// for an established connection, the "login" parameter is silently
    /// ignored on all further calls.
    #[nasl_function(named(login))]
    pub async fn nasl_ssh_set_login(
        &self,
        session_id: SessionId,
        login: Option<&str>,
    ) -> Result<()> {
        let mut session = self.get_by_id(session_id).await?;
        Ok(session.set_opt_user(login)?)
    }

    /// Open a new ssh shell.
    #[nasl_function(named(pty))]
    pub async fn nasl_ssh_shell_open(
        &self,
        session_id: SessionId,
        pty: Option<bool>,
    ) -> Result<SessionId> {
        let mut session = self.get_by_id(session_id).await?;
        let pty = pty.unwrap_or(true);
        session.open_shell(pty).await?;
        Ok(session.id())
    }

    /// Read the output of an ssh shell.
    /// If timeout is given, repeatedly use blocking read until until
    /// there are no more bytes left to read. Otherwise use non_blocking
    /// read mode.
    #[nasl_function]
    pub async fn nasl_ssh_shell_read(
        &self,
        session_id: SessionId,
        timeout: Option<Maybe<u64>>,
    ) -> Result<String> {
        let session = self.get_by_id(session_id).await?;
        let timeout = Duration::from_secs(timeout.and_then(Maybe::as_option).unwrap_or(0));
        let channel = session.get_channel().await?;
        channel.ensure_open()?;

        if timeout.as_secs() > 0 {
            Ok(channel.read_ssh_blocking(timeout)?)
        } else {
            Ok(channel.read_ssh_nonblocking()?)
        }
    }

    /// Write the string `cmd` to an ssh shell.
    #[nasl_function]
    pub async fn nasl_ssh_shell_write(
        &self,
        session_id: SessionId,
        cmd: StringOrData,
    ) -> Result<i32> {
        let session = self.get_by_id(session_id).await?;
        let channel = session.get_channel().await?;
        channel.ensure_open()?;

        let result = match channel.stdin().write_all(cmd.0.as_bytes()) {
            Ok(_) => Ok(0),
            Err(_) => Ok(-1),
        };
        result
    }

    /// Close an ssh shell.
    #[nasl_function]
    pub async fn nasl_ssh_shell_close(&self, session_id: SessionId) -> Result<()> {
        let mut session = self.get_by_id(session_id).await?;
        session.close().await;
        Ok(())
    }

    /// Authenticate a user on an ssh connection
    ///
    /// The function starts the authentication process and pauses it when
    /// it finds the first non-echo prompt. The function expects the session
    /// id as its first unnamed argument.
    /// The first time this function is called for a session id, the named
    /// argument "login" is also expected.
    #[nasl_function(named(login))]
    pub async fn nasl_ssh_login_interactive(
        &self,
        session_id: SessionId,
        login: Option<&str>,
    ) -> Result<Option<String>> {
        let mut session = self.get_by_id(session_id).await?;
        session.ensure_user_set(login)?;
        let methods = session.get_authmethods_cached()?;
        debug!("Available methods:\n{:?}", methods);

        if methods.contains(AuthMethods::INTERACTIVE) {
            let mut prompt = String::new();
            loop {
                let status = session.userauth_keyboard_interactive(None, None)?;
                match status {
                    AuthStatus::Info => {
                        let info = session.userauth_keyboard_interactive_info()?;
                        debug!(
                            name = info.name,
                            instruction = info.instruction,
                            "SSH keyboard-interactive"
                        );

                        for p in info.prompts.into_iter() {
                            if !p.echo {
                                prompt = p.prompt;
                            }
                        }
                        break;
                    }
                    _ => {
                        debug!(
                            "SSH keyboard-interactive authentication failed for session {}",
                            session_id
                        );
                        continue;
                    }
                }
            }
            Ok(Some(prompt))
        } else {
            Ok(None)
        }
    }

    /// Authenticate a user on an ssh connection.
    ///
    /// The function finishes the authentication process started by
    /// ssh_login_interactive.
    #[nasl_function(named(password))]
    pub async fn nasl_ssh_login_interactive_pass(
        &self,
        session_id: SessionId,
        password: &str,
    ) -> Result<()> {
        let session = self.get_by_id(session_id).await?;
        let info = session.userauth_keyboard_interactive_info()?;
        debug!(
            name = info.name,
            instruction = info.instruction,
            "SSH keyboard-interactive"
        );

        let answers: Vec<String> = info
            .prompts
            .into_iter()
            .map(|prompt| if prompt.echo { password } else { "" })
            .map(String::from)
            .collect();
        session.userauth_keyboard_interactive_set_answers(&answers)?;
        loop {
            let status = session.userauth_keyboard_interactive(None, None)?;
            match status {
                AuthStatus::Info => {
                    session.userauth_keyboard_interactive_info().unwrap();
                    continue;
                }
                AuthStatus::Success => break,
                status => {
                    return Err(SshErrorKind::UnexpectedAuthenticationStatus(format!(
                        "{:?}",
                        status
                    ))
                    .with(session_id)
                    .with(ReturnValue(-1)));
                }
            }
        }
        Ok(())
    }

    /// Get the issue banner
    ///
    /// The function returns a string with the issue banner.  This is
    /// usually displayed before authentication.
    #[nasl_function]
    pub async fn nasl_ssh_get_issue_banner(&self, session_id: SessionId) -> Result<Option<String>> {
        let mut session = self.get_by_id(session_id).await?;
        session.ensure_user_set(None)?;
        session.get_authmethods_cached()?;
        Ok(session.get_issue_banner().ok())
    }

    /// The function returns a string with the server banner.  This is
    /// usually the first data sent by the server.
    #[nasl_function]
    pub async fn nasl_ssh_get_server_banner(
        &self,
        session_id: SessionId,
    ) -> Result<Option<String>> {
        let session = self.get_by_id(session_id).await?;
        // TODO: Check with openvas-nasl why the outputs doesn't match
        Ok(session.get_server_banner().ok())
    }

    /// Return a string with comma separated authentication
    /// methods. This is basically the same as returned by
    /// SSH_MSG_USERAUTH_FAILURE protocol element; however, it has been
    /// screened and put into a definitive order.
    #[nasl_function]
    pub async fn nasl_ssh_get_auth_methods(&self, session_id: SessionId) -> Result<Option<String>> {
        let mut session = self.get_by_id(session_id).await?;
        session.ensure_user_set(None)?;
        let authmethods = session.get_authmethods_cached()?;

        let mut methods = vec![];
        if authmethods.contains(AuthMethods::NONE) {
            methods.push("none");
        }
        if authmethods.contains(AuthMethods::PASSWORD) {
            methods.push("password");
        }
        if authmethods.contains(AuthMethods::PUBLIC_KEY) {
            methods.push("publickey");
        }
        if authmethods.contains(AuthMethods::HOST_BASED) {
            methods.push("hostbased");
        }
        if authmethods.contains(AuthMethods::INTERACTIVE) {
            methods.push("keyboard-interactive");
        }

        if methods.is_empty() {
            return Ok(None);
        }
        Ok(Some(methods.join(",")))
    }

    /// Return the MD5 host key.
    #[nasl_function]
    pub async fn nasl_ssh_get_host_key(&self, session_id: SessionId) -> Result<Option<String>> {
        let session = self.get_by_id(session_id).await?;
        let key = session.get_server_public_key()?;
        match key.get_public_key_hash_hexa(PublicKeyHashType::Md5) {
            Ok(hash) => Ok(Some(hash)),
            Err(_) => Ok(None),
        }
    }

    /// Check if the SFTP subsystem is enabled on the remote SSH server.
    #[nasl_function]
    pub async fn nasl_sftp_enabled_check(&self, session_id: SessionId) -> Result<i32> {
        let session = self.get_by_id(session_id).await?;
        match session.sftp() {
            Ok(_) => Ok(0),
            Err(e) => {
                debug!("SFTP enabled check error: {}", e);
                Ok(1)
            }
        }
    }

    /// Execute the NETCONF subsystem on the the ssh channel
    #[nasl_function]
    pub async fn nasl_ssh_execute_netconf_subsystem(
        &self,
        session_id: SessionId,
    ) -> Result<SessionId> {
        let mut session = self.get_by_id(session_id).await?;
        let channel = session.new_channel()?;
        channel.open_session()?;
        channel.request_subsystem("netconf")?;
        session.set_channel(channel);
        Ok(session_id)
    }
}
