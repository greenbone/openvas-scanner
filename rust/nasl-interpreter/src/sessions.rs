// Copyright (C) 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines functions and structures for handling sessions

use std::{
    env,
    sync::{Arc, Mutex},
    time::Duration,
};

use libssh_rs::{AuthMethods, AuthStatus, LogLevel, Session, SshOption};

use crate::{error::FunctionErrorKind, NaslValue};

use std::net::UdpSocket;
use std::os::fd::AsRawFd;

/// Structure to hold connection options
pub struct ConnectionOpts {
    /// Socket to use for the new connection.
    sock: i64,
    /// If no socket is given, use this IP string for the connections
    ip_str: String,
    /// Port to use for the connection
    port: u16,
    /// Timeout for the connection in second
    timeout: i64,
    /// List of the preferred server host key types.
    key_type: String,
    /// SSH client-to-server ciphers.
    csciphers: String,
    /// scciphers SSH server-to-client ciphers.
    scciphers: String,
}

impl ConnectionOpts {
    pub fn new(
        sock: i64,
        ip_str: String,
        port: u16,
        timeout: i64,
        key_type: String,
        csciphers: String,
        scciphers: String,
    ) -> Self {
        Self {
            sock,
            ip_str,
            port,
            timeout,
            key_type,
            csciphers,
            scciphers,
        }
    }
}

/// Structure to hold an SSH Session
pub struct SshSession {
    /// Session ID
    pub session_id: i32,
    /// Ssh Session
    pub session: Session,
    /// Hold the available authentication methods
    pub authmethods: AuthMethods,
    /// Indicating that methods is valid
    pub authmethods_valid: bool,
    /// Set if a user has been set for the session
    pub user_set: bool,
    /// Verbose diagnostic
    pub verbose: i32,
}

impl SshSession {
    pub fn new(
        session_id: i32,
        session: Session,
        authmethods: AuthMethods,
        authmethods_valid: bool,
        user_set: bool,
        verbose: i32,
    ) -> Self {
        Self {
            session_id,
            session,
            authmethods,
            authmethods_valid,
            user_set,
            verbose,
        }
    }

    pub fn set_opt_user(
        &mut self,
        login: &str,
        session_id: i32,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let opt_user = SshOption::User(Some(login.to_string()));
        match self.session.set_option(opt_user) {
            Ok(()) => {
                self.user_set = true;
                Ok(NaslValue::Null)
            }
            Err(e) => Err(FunctionErrorKind::Diagnostic(
                format!(
                    "Failed to set SSH username {} for SessionID {}: {}",
                    login, session_id, e
                ),
                Some(NaslValue::Null),
            )),
        }
    }

    pub fn get_authmethods(&mut self, session_id: i32) -> Result<AuthMethods, FunctionErrorKind> {
        match self.session.userauth_none(None) {
            Ok(libssh_rs::AuthStatus::Success) => {
                //TODO: log the following message:
                //"SSH authentication succeeded using the none method - should not happen; very old server?
                self.authmethods = AuthMethods::NONE;
                Ok(AuthMethods::NONE)
            }
            Ok(libssh_rs::AuthStatus::Denied) => match self.session.userauth_list(None) {
                Ok(list) => {
                    self.authmethods = list;
                    Ok(list)
                }
                Err(_) => {
                    if self.verbose > 0 {
                        //TODO: log the following message:
                        //SSH server did not return a list of authentication methods - trying all
                    }
                    let methods = AuthMethods::HOST_BASED
                        | AuthMethods::INTERACTIVE
                        | AuthMethods::NONE
                        | AuthMethods::PASSWORD
                        | AuthMethods::PUBLIC_KEY;
                    Ok(methods)
                }
            },
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Invalid SSH session for SessionID {}", session_id),
                Some(NaslValue::Null),
            )),
        }
    }
}

impl Default for SshSession {
    fn default() -> Self {
        {
            Self {
                session_id: 50000,
                session: Session::new().unwrap(),
                authmethods: AuthMethods::NONE,
                authmethods_valid: false,
                user_set: false,
                verbose: 0,
            }
        }
    }
}

/// Sessions holder, Holds an array of Tables for different protocols
#[derive(Default)]
pub struct Sessions {
    /// SSH Sessions holder
    pub ssh_sessions: Arc<Mutex<Vec<SshSession>>>,
}

impl Sessions {
    /// Add an SSH session to the Sessions holder
    pub fn add_ssh_session(&self, session: SshSession) {
        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();
        sessions.push(session);
    }
    /// Delete an SSH session to the Sessions holder
    pub fn del_ssh_session(&self, session_id: i32) -> Option<()> {
        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();

        let i = match sessions
            .iter()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((i, _s)) => i,
            _ => return None,
        };

        sessions.remove(i);
        Some(())
    }

    /// Find and return an SSH session by the session ID
    pub fn disconnect_ssh_session(&self, session_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();
        match sessions
            .iter()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_, s)) => {
                s.session.disconnect();
                sessions.remove(session_id as usize);
                Ok(NaslValue::Null)
            }
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Session ID {} not found", session_id),
                Some(NaslValue::Null),
            )),
        }
    }

    /// Establish an ssh session to the host.
    pub fn connect(&self, conn_opts: ConnectionOpts) -> Result<NaslValue, FunctionErrorKind> {
        let session = match Session::new() {
            Ok(s) => s,
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!(
                        "Function called from {}: Failed to set the SSH connection timeout to {} seconds: {}", "func", conn_opts.timeout, e),
                    Some(NaslValue::Null)
                ));
            }
        };

        let option = SshOption::Timeout(Duration::from_secs(conn_opts.timeout as u64));
        match session.set_option(option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} called from {}: Failed to set the SSH connection timeout to {} seconds: {}", "func", "key", conn_opts.timeout, e),
                    Some(NaslValue::Null)
                ));
            }
        };

        let verbose = env::var("OPENVAS_LIBSSH_DEBUG")
            .map(|x| x.parse::<i32>().unwrap_or_default())
            .unwrap_or(0);
        let log_level = match verbose {
            verbose if verbose <= 0 => LogLevel::NoLogging,
            verbose if verbose <= 1 => LogLevel::Warning,
            verbose if verbose <= 2 => LogLevel::Protocol,
            verbose if verbose <= 3 => LogLevel::Packet,
            _ => LogLevel::Functions,
        };
        let option = SshOption::LogLevel(log_level);
        match session.set_option(option) {
            Ok(_) => (),
            Err(_) => return Ok(NaslValue::Null),
        };

        let option = SshOption::Hostname(conn_opts.ip_str.to_owned());
        match session.set_option(option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} (calling internal function {}): Failed to set SSH hostname '{}': {}", "func", "nasl_ssh_connect", conn_opts.ip_str, e),
                    Some(NaslValue::Null)
                ));
            }
        };

        let option = SshOption::KnownHosts(Some("/dev/null".to_owned()));
        match session.set_option(option) {
            Ok(_) => (),
            Err(e) => {
                FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} (calling internal function {}): Failed to disable known_hosts: {}",
                        "func", "nasl_ssh_connect", e
                    ),
                    Some(NaslValue::Null),
                );
            }
        };

        if !conn_opts.key_type.is_empty() {
            let option = SshOption::PublicKeyAcceptedTypes(conn_opts.key_type.to_owned());
            match session.set_option(option) {
                Ok(_) => (),
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!(
                            "Function {} (calling internal function {}): Failed to set SSH key type '{}': {}", "func", "nasl_ssh_connect", conn_opts.key_type, e),
                        Some(NaslValue::Null)
                    ));
                }
            };
        }

        if !conn_opts.csciphers.is_empty() {
            let option = SshOption::CiphersCS(conn_opts.csciphers.to_owned());
            match session.set_option(option) {
                Ok(_) => (),
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!(
                            "Function {} (calling internal function {}): Failed to set SSH client to server ciphers '{}': {}", "func", "nasl_ssh_connect", conn_opts.csciphers, e),
                        Some(NaslValue::Null)
                    ));
                }
            };
        }

        if !conn_opts.scciphers.is_empty() {
            let option = SshOption::CiphersSC(conn_opts.scciphers.to_owned());
            match session.set_option(option) {
                Ok(_) => (),
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!(
                            "Function {} (calling internal function {}): Failed to set SSH server to client ciphers '{}': {}", "func", "nasl_ssh_connect", conn_opts.scciphers, e),
                        Some(NaslValue::Null)
                    ));
                }
            };
        }

        let valid_ports = 1..65535;
        if valid_ports.contains(&conn_opts.port) {
            let option = SshOption::Port(conn_opts.port);
            match session.set_option(option) {
                Ok(_) => (),
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!(
                            "Function {} (calling internal function {}) called from {}: Failed to set SSH port '{}': {}", "func", "nasl_ssh_connect", "key", conn_opts.port, e),
                        Some(NaslValue::Null),
                    ));
                }
            };
        }

        let mut forced_sock = -1;
        if conn_opts.sock > 0 {
            // This is a fake raw socket.
            // TODO: implement openvas_get_socket_from_connection()
            let my_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let option = SshOption::Socket(my_sock.as_raw_fd());

            if verbose > 0 {
                //TODO: use ctx.logger().info() ?
                println!(
                    "{}",
                    format_args!(
                        "Setting SSH fd for '{}' to {} (NASL sock={}",
                        conn_opts.ip_str,
                        my_sock.as_raw_fd(),
                        conn_opts.sock
                    )
                );
            }

            match session.set_option(option) {
                Ok(_) => (),
                Err(e) => {
                    return Err(FunctionErrorKind::Diagnostic(
                        format!(
                            "Function {} (calling internal function {}) called from {}: Failed to set SSH fd for '{}' to {} (NASL sock={}): {}", "func", "nasl_ssh_connect", "key", conn_opts.ip_str, my_sock.as_raw_fd(), conn_opts.sock, e), // TODO: get_nasl_function_name()
                        Some(NaslValue::Null),
                    ));
                }
            };

            forced_sock = conn_opts.sock; // TODO: check and fix everything related to open socket
        }

        if verbose > 0 {
            // TODO ctx.logger().info
            println!(
                "{}",
                format_args!(
                    "Connecting to SSH server '{}' (port {}, sock {})",
                    conn_opts.ip_str, conn_opts.port, conn_opts.sock
                )
            );
        }

        let session_id = 9000; //TODO: implement next_session_id()
        let ret_session_id = match session.connect() {
            Ok(_) => Ok(NaslValue::Number(session_id as i64)),
            Err(e) => {
                session.disconnect();
                Err(FunctionErrorKind::Diagnostic(
                    format!(
                        "Failed to connect to SSH server '{}' (port {}, sock {}, f={}): {}",
                        conn_opts.ip_str, conn_opts.port, conn_opts.sock, forced_sock, e
                    ),
                    Some(NaslValue::Null),
                ))
            }
        };

        let authmethods_valid = false;
        let authmethods = AuthMethods::NONE;
        let user_set = false;
        let s = SshSession {
            session_id,
            session,
            authmethods,
            authmethods_valid,
            user_set,
            verbose,
        };

        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();
        sessions.push(s);

        ret_session_id
    }

    /// Set the login name for the authentication.
    pub fn set_ssh_login(
        &self,
        session_id: i32,
        login: &str,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, s)) => s.set_opt_user(login, session_id),
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Session ID {} not found", session_id),
                Some(NaslValue::Null),
            )),
        }
    }

    /// Authenticate a user on an ssh connection
    pub fn set_ssh_userauth(
        &self,
        session_id: i32,
        login: &str,
        password: &str,
        privatekey: &str,
        passphrase: &str,
    ) -> Result<NaslValue, FunctionErrorKind> {
        if password.is_empty() && privatekey.is_empty() && passphrase.is_empty() {
            // TODO: get from the host kb.
            return Err(FunctionErrorKind::Diagnostic(
                format!("Invalid SSH session for SessionID {}", session_id),
                Some(NaslValue::Null),
            ));
        }

        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                if !session.user_set {
                    session.set_opt_user(login, session_id)?;
                }
                let verbose = session.verbose > 0;
                let methods: AuthMethods = {
                    if !session.authmethods_valid {
                        session.get_authmethods(session_id)?
                    } else {
                        session.authmethods
                    }
                };
                if verbose {
                    // TODO: print available methods maybe with ctx.logger?
                    //println!(format!("Available methods:\n{:?}", methods));
                }

                if methods == AuthMethods::NONE {
                    return Ok(NaslValue::Number(0));
                }

                /* Check whether a password has been given.  If so, try to
                authenticate using that password.  Note that the OpenSSH client
                uses a different order it first tries the public key and then the
                password.  However, the old NASL SSH protocol implementation tries
                the password before the public key authentication.  Because we
                want to be compatible, we do it in that order. */
                if !password.is_empty() && methods.contains(AuthMethods::PASSWORD) {
                    match session.session.userauth_password(None, Some(password)) {
                        Ok(AuthStatus::Success) => {
                            return Ok(NaslValue::Number(0));
                        }
                        Ok(_) => {
                            if verbose {
                                println!(
                                    "SSH password authentication failed for session {}",
                                    session_id
                                );
                            }
                        }
                        Err(_) => {
                            return Err(FunctionErrorKind::Diagnostic(
                                format!(
                                    "Failed setting user authentication for SessionID {}",
                                    session_id
                                ),
                                Some(NaslValue::Null),
                            ));
                        }
                    };
                }

                /* Our strategy for kbint is to send the password to the first
                prompt marked as non-echo.  */
                if !password.is_empty() && methods.contains(AuthMethods::INTERACTIVE) {
                    loop {
                        match session.session.userauth_keyboard_interactive(None, None) {
                            Ok(AuthStatus::Info) => {
                                let info = match session
                                    .session
                                    .userauth_keyboard_interactive_info()
                                {
                                    Ok(i) => i,
                                    Err(_) => {
                                        return Err(FunctionErrorKind::Diagnostic(
                                        format!("Failed setting user authentication for SessionID {}", session_id),
                                        Some(NaslValue::Null),
                                    ));
                                    }
                                };
                                if verbose {
                                    println!("SSH kbdint name={}", info.name);
                                    println!("SSH kbdint instruction{}", info.instruction);
                                }

                                let mut answers: Vec<String> = Vec::new();
                                for p in info.prompts.into_iter() {
                                    if p.echo {
                                        answers.push(password.to_string());
                                    } else {
                                        answers.push(String::new());
                                    };
                                }
                                match session
                                    .session
                                    .userauth_keyboard_interactive_set_answers(&answers)
                                {
                                    Ok(_) => {
                                        return Ok(NaslValue::Number(0));
                                    }
                                    Err(_) => break,
                                }
                            }
                            Ok(_) => {
                                if verbose {
                                    println!("SSH keyboard-interactive authentication failed for session {}", session_id);
                                };
                                continue;
                            }
                            Err(_) => {
                                return Err(FunctionErrorKind::Diagnostic(
                                    format!(
                                        "Failed setting user authentication for SessionID {}",
                                        session_id
                                    ),
                                    Some(NaslValue::Null),
                                ));
                            }
                        };
                    }
                };

                // If we have a private key, try public key authentication.
                if privatekey.is_empty() && methods.contains(AuthMethods::PUBLIC_KEY) {
                    // TODO: Not implemented. Not supported method
                };

                Ok(NaslValue::Number(0))
            }
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Session ID {} not found", session_id),
                Some(NaslValue::Null),
            )),
        }
    }

    /// Return the an SSH session ID given a sock FD
    pub fn session_id_from_sock(&self, _sock: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Given a session id, return the corresponding socket
    pub fn get_sock(&self, _sesion_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Authenticate a user on an ssh connection
    pub fn login_interactive(
        &self,
        _session_id: i32,
        _login: &str,
    ) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Authenticate a user on an ssh connection
    pub fn login_interactive_pass(
        &self,
        _session_id: i32,
        _password: &str,
    ) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Run a command via ssh.
    pub fn request_exec(
        &self,
        _session_id: i32,
        _cmd: &str,
        _stdout: i32,
        _stderr: i32,
    ) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Request an ssh shell
    pub fn shell_open(
        &self,
        //session id, &login
        _session_id: i32,
        _pty: bool,
    ) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Read the output of an ssh shell.
    pub fn shell_read(
        &self,
        _session_id: i32,
        _timeout: Duration,
    ) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }
    /// Write string to ssh shell
    pub fn shell_write(
        &self,
        _session_id: i32,
        _cmd: &str,
    ) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Close an ssh shell
    pub fn shell_close(&self, _session_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Get the issue banner
    pub fn get_issue_banner(&self, _session_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Get the server banner
    pub fn get_server_banner(&self, _session_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Get the list of authmethods
    pub fn get_auth_methods(&self, _session_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Get the host key
    pub fn get_host_key(&self, _session_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }

    /// Get the host key
    pub fn sftp_enabled_check(&self, _session_id: i32) -> Result<NaslValue, FunctionErrorKind> {
        Ok(NaslValue::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session() {
        let s = Sessions::default();
        s.add_ssh_session(SshSession::default());
        assert_eq!(s.ssh_sessions.as_ref().lock().iter().len(), 1);
    }

    #[test]
    fn delete_session() {
        let st = Sessions::default();
        let s = SshSession::default();
        let id = s.session_id;
        st.add_ssh_session(s);
        assert_eq!(st.del_ssh_session(id), Some(()));
        assert_eq!(st.del_ssh_session(id), None);
    }
}
