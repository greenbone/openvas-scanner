// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// TODO replace if (verbose) calls to debug calls
// TODO make error handling less redundant
// TODO clean up and maybe split as 2000 lines is a bit much
//! Defines NASL ssh and sftp functions
//!
mod sessions;

use core::str;
use libssh_rs::{AuthMethods, AuthStatus, Channel, LogLevel, Session, SshKey, SshOption};
use nasl_builtin_utils::{Context, ContextType, FunctionErrorKind, Register};
use nasl_syntax::logger::NaslLogger;
use nasl_syntax::NaslValue;
use sessions::SshSession;
use std::io::Write;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::MutexGuard;
use std::{
    env,
    sync::{Arc, Mutex},
    time::Duration,
};

type NaslSSHFunction<K> = fn(&Ssh, &Register, &Context<K>) -> Result<NaslValue, FunctionErrorKind>;

fn read_ssh_blocking(channel: &Channel, timeout: Duration, response: &mut String) -> i32 {
    let mut buf: [u8; 4096] = [0; 4096];

    // read stderr
    loop {
        match channel.read_timeout(&mut buf, true, Some(timeout)) {
            Ok(0) => break,
            // that looks buggy, on TryAgain we should continue without reading the buffer
            Ok(_) | Err(libssh_rs::Error::TryAgain) => {
                let buf_as_str = match std::str::from_utf8(&buf) {
                    Ok(s) => s,
                    Err(_) => {
                        return -1;
                    }
                };
                response.push_str(buf_as_str);
            }
            Err(_) => {
                return -1;
            }
        }
    }
    // read stdout
    loop {
        match channel.read_timeout(&mut buf, false, Some(timeout)) {
            Ok(0) => break,
            Ok(_) | Err(libssh_rs::Error::TryAgain) => {
                let buf_as_str = match std::str::from_utf8(&buf) {
                    Ok(s) => s,
                    Err(_) => {
                        return -1;
                    }
                };
                response.push_str(buf_as_str);
            }
            Err(_) => {
                return -1;
            }
        }
    }

    0
}

fn read_ssh_nonblocking(channel: &Channel, response: &mut String) -> i32 {
    if channel.is_closed() || channel.is_eof() {
        return -1;
    }

    let mut buf: [u8; 4096] = [0; 4096];
    // stderr
    match channel.read_nonblocking(&mut buf, true) {
        Ok(n) if n > 0 => {
            let buf_as_str = match std::str::from_utf8(&buf) {
                Ok(s) => s,
                Err(_) => {
                    return -1;
                }
            };
            response.push_str(buf_as_str);
        }
        Ok(_) => (),
        Err(_) => {
            return -1;
        }
    }

    let mut buf: [u8; 4096] = [0; 4096];
    // stdout
    match channel.read_nonblocking(&mut buf, false) {
        Ok(n) if n > 0 => {
            let buf_as_str = match std::str::from_utf8(&buf) {
                Ok(s) => s,
                Err(_) => {
                    return -1;
                }
            };
            response.push_str(buf_as_str);
        }
        Ok(_) => (),
        Err(_) => {
            return -1;
        }
    }
    0
}
/// Request and set a shell. It set the pty if necessary.
fn request_ssh_shell(
    session_id: i32,
    channel: &mut Channel,
    pty: bool,
) -> Result<(), FunctionErrorKind> {
    if pty {
        match channel.request_pty("xterm", 80, 24) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!(
                        "Failed to requesting a new channel pty for session ID {}: {}",
                        session_id, e
                    ),
                    Some(NaslValue::Number(-1)),
                ));
            }
        }
    }

    match channel.request_shell() {
        Ok(_) => Ok(()),
        Err(e) => Err(FunctionErrorKind::Diagnostic(
            format!(
                "Failed to open a shell for session ID {}: {}",
                session_id, e
            ),
            Some(NaslValue::Number(-1)),
        )),
    }
}

/// Return the next available session ID
fn next_session_id(sessions: &MutexGuard<Vec<SshSession>>) -> i32 {
    // Note that the first session ID we will
    // hand out is an arbitrary high number, this is only to help
    // debugging.
    let mut new_val: i32 = 9000;
    if sessions.is_empty() {
        return new_val;
    }

    let mut list = sessions.iter().map(|x| x.session_id).collect::<Vec<i32>>();
    list.sort();

    for (i, v) in list.iter().enumerate() {
        if i == list.len() - 1 {
            new_val = v + 1;
            break;
        }
        if new_val != list[i] {
            break;
        }

        new_val += 1;
    }
    new_val
}

fn lock_sessions(
    sessions: &Arc<Mutex<Vec<SshSession>>>,
) -> Result<MutexGuard<Vec<SshSession>>, FunctionErrorKind> {
    // we actually need to panic as a lock error is fatal
    // alternatively we need to add a poison error on FunctionErrorKind
    Ok(Arc::as_ref(sessions).lock().unwrap())
}

fn set_opt_user(
    ssh_session: &mut SshSession,
    login: Option<String>,
    session_id: i32,
) -> Result<NaslValue, FunctionErrorKind> {
    // TODO: get the username alternatively from the kb.
    let opt_user = SshOption::User(login.clone());
    match ssh_session.session.set_option(opt_user) {
        Ok(()) => {
            ssh_session.user_set = true;
            Ok(NaslValue::Null)
        }
        Err(e) => Err(FunctionErrorKind::Diagnostic(
            format!(
                "Failed to set SSH username {} for SessionID {}: {}",
                login.unwrap_or_default(),
                session_id,
                e
            ),
            Some(NaslValue::Null),
        )),
    }
}

fn get_authmethods(
    session: &mut SshSession,
    session_id: i32,
    logger: &dyn NaslLogger,
) -> Result<AuthMethods, FunctionErrorKind> {
    match session.session.userauth_none(None) {
        Ok(libssh_rs::AuthStatus::Success) => {
            logger.info(&"SSH authentication succeeded using the none method - should not happen; very old server?");
            session.authmethods = AuthMethods::NONE;
            session.authmethods_valid = true;
            Ok(AuthMethods::NONE)
        }
        Ok(libssh_rs::AuthStatus::Denied) => match session.session.userauth_list(None) {
            Ok(list) => {
                session.authmethods = list;
                session.authmethods_valid = true;
                Ok(list)
            }
            Err(_) => {
                logger.debug(
                    &"SSH server did not return a list of authentication methods - trying all"
                        .to_string(),
                );
                let methods = AuthMethods::HOST_BASED
                    | AuthMethods::INTERACTIVE
                    | AuthMethods::NONE
                    | AuthMethods::PASSWORD
                    | AuthMethods::PUBLIC_KEY;
                session.authmethods_valid = true;
                Ok(methods)
            }
        },
        _ => Err(FunctionErrorKind::Diagnostic(
            format!("Invalid SSH session for SessionID {}", session_id),
            Some(NaslValue::Null),
        )),
    }
}

fn channel_read(
    channel: &Channel,
    cmd: &str,
    session_id: i32,
    stderr: bool,
    timeout: Option<Duration>,
) -> Result<String, FunctionErrorKind> {
    let mut buf: [u8; 4096] = [0; 4096];
    let mut buf_as_str = String::new();
    loop {
        match channel.read_timeout(&mut buf, stderr, timeout) {
            Ok(0) => break,
            Ok(_) => {
                buf_as_str = match std::str::from_utf8(&buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(FunctionErrorKind::Diagnostic(
                            format!(
                                "Channel failed getting response {} for session ID {}",
                                cmd, session_id
                            ),
                            Some(NaslValue::Number(-1)),
                        ));
                    }
                };
            }
            Err(_) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!(
                        "Channel failed getting response {} for session ID {}",
                        cmd, session_id
                    ),
                    Some(NaslValue::Number(-1)),
                ));
            }
        }
    }
    Ok(buf_as_str)
}

fn exec_ssh_cmd(
    session: &SshSession,
    cmd: &str,
    verbose: bool,
    compat_mode: bool,
    to_stdout: i32,
    to_stderr: i32,
    logger: &dyn NaslLogger,
) -> Result<(String, String), FunctionErrorKind> {
    let channel = match session.session.new_channel() {
        Ok(c) => c,
        Err(e) => {
            return Err(FunctionErrorKind::Diagnostic(
                format!(
                    "Failed to open a new channel for session ID {}: {}",
                    session.session_id, e
                ),
                Some(NaslValue::Number(-1)),
            ));
        }
    };

    match channel.open_session() {
        Ok(_) => (),
        Err(e) => {
            return Err(FunctionErrorKind::Diagnostic(
                format!(
                    "Channel failed to open session for session ID {}: {}",
                    session.session_id, e
                ),
                Some(NaslValue::Number(-1)),
            ));
        }
    }

    match channel.request_pty("xterm", 80, 24) {
        Ok(_) => (),
        Err(e) => {
            if verbose {
                logger.info(&format!(
                    "Channel failed to request pty for session ID {}: {}",
                    session.session_id, e
                ));
            }
        }
    }

    match channel.request_exec(cmd) {
        Ok(_) => (),
        Err(e) => {
            return Err(FunctionErrorKind::Diagnostic(
                format!(
                    "Channel failed to exec command {} for session ID {}: {}",
                    cmd, session.session_id, e
                ),
                Some(NaslValue::Number(-1)),
            ));
        }
    }

    let mut response = String::new();
    let mut compat_buf = String::new();

    //Read stderr
    let stderr_read = channel_read(
        &channel,
        cmd,
        session.session_id,
        true,
        Some(Duration::from_millis(15000)),
    )?;
    if to_stderr == 1 {
        response.push_str(stderr_read.as_str());
    }
    if compat_mode {
        compat_buf.push_str(stderr_read.as_str());
    }

    //Read stdout
    let stdout_read = channel_read(
        &channel,
        cmd,
        session.session_id,
        false,
        Some(Duration::from_millis(15000)),
    )?;
    if to_stdout == 1 {
        response.push_str(stdout_read.as_str());
    }

    Ok((response, compat_buf))
}

#[derive(Default)]
pub struct Ssh {
    sessions: Arc<Mutex<Vec<SshSession>>>,
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
    fn nasl_ssh_connect<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let sock: i64 = register
            .named("socket")
            .unwrap_or(&ContextType::Value(NaslValue::Number(0)))
            .into();

        let port = if sock > 0 {
            0u16 // ignore the port if there is a socket
        } else {
            match register.named("port") {
                Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
                _ => 0u16, // TODO: implement get_ssh_port()
            }
        };

        let ip_str: String = match ctx.target() {
            x if !x.is_empty() => x.to_string(),
            _ => "127.0.0.1".to_string(),
        };

        let timeout: i64 = register
            .named("timeout")
            .unwrap_or(&ContextType::Value(NaslValue::Number(0)))
            .into();
        let key_type: String = register
            .named("keytype")
            .unwrap_or(&ContextType::Value(NaslValue::String(String::default())))
            .into();
        let csciphers: String = register
            .named("csciphers")
            .unwrap_or(&ContextType::Value(NaslValue::String(String::default())))
            .into();

        let scciphers: String = register
            .named("scciphers")
            .unwrap_or(&ContextType::Value(NaslValue::String(String::default())))
            .into();

        let session = match Session::new() {
            Ok(s) => s,
            Err(e) => {
                return Err(FunctionErrorKind::Dirty(format!(
                    "Function called from ssh_connect: {}",
                    e
                )));
            }
        };

        let option = SshOption::Timeout(Duration::from_secs(timeout as u64));

        if let Err(err) = session.set_option(option) {
            return Err(FunctionErrorKind::Dirty(
            format!(
                "Function {} called from {}: Failed to set the SSH connection timeout to {} seconds: {}", "func", "key", timeout, err)));
        }

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
        if session.set_option(option).is_err() {
            return Err(FunctionErrorKind::Dirty(format!(
                "Function {} called from {}: Failed to set the SSH connection log level",
                "func", "key"
            )));
        }

        let option = SshOption::Hostname(ip_str.to_owned());
        match session.set_option(option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionErrorKind::Dirty(
                format!(
                    "Function {} (calling internal function {}): Failed to set SSH hostname '{}': {}", "func", "nasl_ssh_connect", ip_str, e)
            ));
            }
        };

        let option = SshOption::KnownHosts(Some("/dev/null".to_owned()));
        if let Err(err) = session.set_option(option) {
            return Err(FunctionErrorKind::Dirty(format!(
                "Function {} (calling internal function {}): Failed to disable known_hosts: {}",
                "func", "nasl_ssh_connect", err
            )));
        }

        if !key_type.is_empty() {
            let option = SshOption::HostKeys(key_type.to_owned());
            if let Err(err) = session.set_option(option) {
                return Err(FunctionErrorKind::Dirty(
                format!(
                    "Function {} (calling internal function {}): Failed to set SSH key type '{}': {}", "func", "nasl_ssh_connect", key_type, err)
                ));
            }
        }

        if !csciphers.is_empty() {
            let option = SshOption::CiphersCS(csciphers.to_owned());
            if let Err(err) = session.set_option(option) {
                return Err(FunctionErrorKind::Dirty(
                format!(
                    "Function {} (calling internal function {}): Failed to set SSH client to server ciphers '{}': {}", "func", "nasl_ssh_connect", csciphers, err)
            ));
            }
        }

        if !scciphers.is_empty() {
            let option = SshOption::CiphersSC(scciphers.to_owned());
            if let Err(err) = session.set_option(option) {
                return Err(FunctionErrorKind::Dirty(
                format!(
                    "Function {} (calling internal function {}): Failed to set SSH server to client ciphers '{}': {}", "func", "nasl_ssh_connect", scciphers, err)
            ));
            }
        }

        let valid_ports = 1..65535;
        if valid_ports.contains(&port) {
            let option = SshOption::Port(port);
            if let Err(err) = session.set_option(option) {
                return Err(FunctionErrorKind::Dirty(
                format!(
                    "Function {} (calling internal function {}) called from {}: Failed to set SSH port '{}': {}", "func", "nasl_ssh_connect", "key", port, err)
            ));
            }
        }

        let mut forced_sock = -1;
        if sock > 0 {
            // This is a fake raw socket.
            // TODO: implement openvas_get_socket_from_connection()
            let my_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let option = SshOption::Socket(my_sock.as_raw_fd());

            if verbose > 0 {
                ctx.logger().info(&format!(
                    "Setting SSH fd for '{}' to {} (NASL sock={}",
                    ip_str,
                    my_sock.as_raw_fd(),
                    sock
                ));
            }

            if let Err(err) = session.set_option(option) {
                return Err(FunctionErrorKind::Dirty(
                format!(
                    "Function {} called from {}: Failed to set SSH fd for '{}' to {} (NASL sock={}): {}", "nasl_ssh_connect", "key", ip_str, my_sock.as_raw_fd(), sock, err)
            ));
            }

            forced_sock = sock; // TODO: check and fix everything related to open socket
        }

        if verbose > 0 {
            ctx.logger().info(&format!(
                "Connecting to SSH server '{}' (port {}, sock {})",
                ip_str, port, sock
            ));
        }

        match session.connect() {
            Ok(_) => {
                let mut sessions = lock_sessions(&self.sessions)?;

                let session_id = next_session_id(&sessions);

                let s = SshSession {
                    session_id,
                    session,
                    authmethods: AuthMethods::NONE,
                    authmethods_valid: false,
                    user_set: false,
                    verbose,
                    channel: None,
                };

                sessions.push(s);

                Ok(NaslValue::Number(session_id as i64))
            }
            Err(e) => {
                session.disconnect();
                Err(FunctionErrorKind::Dirty(format!(
                    "Failed to connect to SSH server '{}' (port {}, sock {}, f={}): {}",
                    ip_str, port, sock, forced_sock, e
                )))
            }
        }
    }

    /// Disconnect an ssh connection

    /// This function takes the ssh session id (as returned by ssh_connect)
    /// as its only unnamed argument.  Passing 0 as session id is
    /// explicitly allowed and does nothing.  If there are any open
    /// channels they are closed as well and their ids will be marked as
    /// invalid.
    ///
    /// nasl params
    /// - An SSH session id.  A value of 0 is allowed and acts as a NOP.
    fn nasl_ssh_disconnect<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        };

        match &positional[0] {
            NaslValue::Number(session_id) => {
                let mut sessions = lock_sessions(&self.sessions)?;
                match sessions
                    .iter()
                    .enumerate()
                    .find(|(_i, s)| s.session_id == *session_id as i32)
                {
                    Some((i, s)) => {
                        s.session.disconnect();
                        sessions.remove(i);
                        Ok(NaslValue::Null)
                    }
                    _ => Err(FunctionErrorKind::Diagnostic(
                        format!("Session ID {} not found", session_id),
                        Some(NaslValue::Null),
                    )),
                }
            }
            _ => Err(FunctionErrorKind::WrongArgument(
                ("Invalid Session ID").to_string(),
            )),
        }
    }

    /// Given a socket, return the corresponding session id.
    /// nasl params
    /// - A NASL socket value
    ///
    /// return An integer with the corresponding ssh session id or 0 if
    ///          no session id is known for the given socket.
    fn nasl_ssh_session_id_from_sock<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        match &positional[0] {
            NaslValue::Number(_x) => Ok(NaslValue::Null),
            _ => Err(FunctionErrorKind::WrongArgument(
                ("Invalid socket FD").to_string(),
            )),
        }
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
    fn nasl_ssh_get_sock<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        match &positional[0] {
            NaslValue::Number(_x) => Ok(NaslValue::Null),
            _ => Err(FunctionErrorKind::WrongArgument(
                ("Invalid session ID").to_string(),
            )),
        }
    }
    /// Set the login name for the authentication.
    ///  
    /// This is an optional function and usuallay not required.  However,
    /// if you want to get the banner before starting the authentication,
    /// you need to tell libssh the user because it is often not possible
    /// to change the user after the first call to an authentication
    /// methods - getting the banner uses an authentication function.
    ///  
    /// The named argument "login" is used for the login name; it defaults
    /// the KB entry "Secret/SSH/login".  It should contain the user name
    /// to login.  Given that many servers don't allow changing the login
    /// for an established connection, the "login" parameter is silently
    /// ignored on all further calls.
    ///  
    /// nasl params
    /// - An SSH session id.
    ///  
    /// nasl named params
    /// - login: A string with the login name (optional).
    fn nasl_ssh_set_login<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let login = match register.named("login") {
            Some(ContextType::Value(NaslValue::String(x))) => Some(x.to_owned()),
            _ => return Err(FunctionErrorKind::from("login")),
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, s)) => set_opt_user(s, login, session_id),
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
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
    fn nasl_ssh_userauth<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        // Login is optional. It must be later check if the login was
        // already set by another option.
        let login = match register.named("login") {
            Some(ContextType::Value(NaslValue::String(x))) => Some(x.to_owned()),
            None => None,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid value for login").to_string(),
                ))
            }
        };

        let password = match register.named("password") {
            Some(ContextType::Value(NaslValue::String(x))) => Some(x.as_str()),
            None => None,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid value for password").to_string(),
                ))
            }
        };

        let privatekey = match register.named("privatekey") {
            Some(ContextType::Value(NaslValue::String(x))) => Some(x.as_str()),
            None => None,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid value for privatekey").to_string(),
                ))
            }
        };
        let passphrase = match register.named("passphrase") {
            Some(ContextType::Value(NaslValue::String(x))) => Some(x.as_str()),
            None => None,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid invalid value for passphrase").to_string(),
                ))
            }
        };

        if password.is_none() && privatekey.is_none() && passphrase.is_none() {
            //TODO: Get values from KB
            return Err(FunctionErrorKind::Dirty(format!(
                "Invalid SSH session for SessionID {}",
                session_id
            )));
        }

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                if !session.user_set {
                    set_opt_user(session, login, session_id)?;
                }
                let verbose = session.verbose > 0;

                // Get the authentication methods only once per session.
                let methods: AuthMethods = {
                    if !session.authmethods_valid {
                        get_authmethods(session, session_id, ctx.logger())?
                    } else {
                        session.authmethods
                    }
                };
                if verbose {
                    ctx.logger()
                        .info(&format!("Available methods:\n{:?}", methods));
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
                if password.is_some() && methods.contains(AuthMethods::PASSWORD) {
                    match session.session.userauth_password(None, password) {
                        Ok(AuthStatus::Success) => {
                            return Ok(NaslValue::Number(0));
                        }
                        Ok(_) => {
                            if verbose {
                                ctx.logger().info(&format!(
                                    "SSH password authentication failed for session {}",
                                    session_id
                                ));
                            }
                        }
                        Err(_) => {
                            return Err(FunctionErrorKind::Dirty(format!(
                                "Failed setting user authentication for SessionID {}",
                                session_id
                            )));
                        }
                    };
                }

                /* Our strategy for kbint is to send the password to the first
                prompt marked as non-echo.  */
                if password.is_some() && methods.contains(AuthMethods::INTERACTIVE) {
                    loop {
                        match session.session.userauth_keyboard_interactive(None, None) {
                            Ok(AuthStatus::Info) => {
                                let info =
                                    match session.session.userauth_keyboard_interactive_info() {
                                        Ok(i) => i,
                                        Err(_) => {
                                            return Err(FunctionErrorKind::Dirty(format!(
                                            "Failed setting user authentication for SessionID {}",
                                            session_id
                                        )));
                                        }
                                    };
                                if verbose {
                                    ctx.logger().info(&format!("SSH kbdint name={}", info.name));
                                    ctx.logger().info(&format!(
                                        "SSH kbdint instruction{}",
                                        info.instruction
                                    ));
                                }

                                let mut answers: Vec<String> = Vec::new();
                                for p in info.prompts.into_iter() {
                                    if !p.echo {
                                        answers.push(password.unwrap_or_default().to_string());
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
                                    ctx.logger().info(&format!(
                                    "SSH keyboard-interactive authentication failed for session {}",
                                    session_id));
                                };
                                continue;
                            }
                            Err(_) => {
                                return Err(FunctionErrorKind::Dirty(format!(
                                    "Failed setting user authentication for SessionID {}",
                                    session_id
                                )));
                            }
                        };
                    }
                };

                // If we have a private key, try public key authentication.
                if privatekey.is_none() && methods.contains(AuthMethods::PUBLIC_KEY) {
                    match SshKey::from_privkey_base64(privatekey.unwrap_or_default(), passphrase) {
                        Ok(k) => match session.session.userauth_try_publickey(None, &k) {
                            Ok(AuthStatus::Success) => {
                                match session.session.userauth_publickey(None, &k) {
                                    Ok(AuthStatus::Success) => {
                                        return Ok(NaslValue::Number(0));
                                    }
                                    _ => {
                                        if verbose {
                                            ctx.logger().info(&format!("SSH authentication failed for session {}: No more authentication methods to try", session_id));
                                        };
                                    }
                                }
                            }
                            _ => {
                                if verbose {
                                    ctx.logger().info(&format!("SSH public key authentication failed for session {}: Server does not want our key", session_id));
                                };
                            }
                        },
                        Err(_) => {
                            if verbose {
                                ctx.logger().info(&format!("SSH public key authentication failed for session {}: Error converting provided key", session.session_id));
                            };
                        }
                    };
                };
                Ok(NaslValue::Number(0))
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
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
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// nasl named params
    ///
    /// - cmd: A string with the command to execute.
    ///
    /// - stdout: An integer with value 0 or 1; see above for a full
    ///    description.
    ///
    /// - stderr: An integer with value 0 or 1; see above for a full
    ///    description.
    ///
    /// return A data block on success or NULL on error.
    fn nasl_ssh_request_exec<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let cmd = match register.named("cmd") {
            Some(ContextType::Value(NaslValue::String(x))) => x,
            _ => return Err(FunctionErrorKind::from("No command passed")),
        };

        let stdout = match register.named("stdout") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => -1,
        };

        let stderr = match register.named("stderr") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
            _ => -1,
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                let verbose = session.verbose > 0;

                if cmd.is_empty() {
                    return Ok(NaslValue::Null);
                }
                let (mut to_stdout, mut to_stderr, mut compat_mode): (i32, i32, bool) =
                    (stdout, stderr, false);
                if stdout == -1 && stderr == -1 {
                    // None of the two named args are given.
                    to_stdout = 1;
                } else if stdout == 0 && stderr == 0 {
                    // Comaptibility mode
                    to_stdout = 1;
                    compat_mode = true;
                }

                if to_stdout < 0 {
                    to_stdout = 0;
                }
                if to_stderr < 0 {
                    to_stderr = 0;
                }

                let (mut response, compat_buf) = exec_ssh_cmd(
                    session,
                    cmd,
                    verbose,
                    compat_mode,
                    to_stdout,
                    to_stderr,
                    ctx.logger(),
                )?;

                if compat_mode {
                    response.push_str(&compat_buf)
                }
                Ok(NaslValue::String(response))
            }
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Session ID {} not found", session_id),
                Some(NaslValue::Number(-1)),
            )),
        }
    }

    /// Request an ssh shell.
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// nasl named params
    ///
    /// - pty: To enable/disable the interactive shell. Default is 1 (interactive).
    ///
    /// @naslret An int on success or NULL on error.
    fn nasl_ssh_shell_open<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let pty = match register.named("pty") {
            Some(ContextType::Value(NaslValue::Boolean(x))) => *x,
            _ => false,
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                // new channel
                let mut channel = match session.session.new_channel() {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(FunctionErrorKind::Dirty(format!(
                            "Failed to open a new channel for session ID {}: {}",
                            session.session_id, e
                        )));
                    }
                };

                match channel.open_session() {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(FunctionErrorKind::Dirty(format!(
                            "Channel failed to open session for session ID {}: {}",
                            session.session_id, e
                        )));
                    }
                };

                request_ssh_shell(session_id, &mut channel, pty)?;

                session.channel = Some(channel);
                Ok(NaslValue::Number(session_id as i64))
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Read the output of an ssh shell.
    /// nasl params
    /// - An SSH session id.
    ///
    /// nasl named params
    /// - timeout: Enable the blocking ssh read until it gives the timeout or there is no
    /// bytes left to read.
    ///
    /// return A string on success or NULL on error.
    fn nasl_ssh_shell_read<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let timeout = match register.named("timeout") {
            Some(ContextType::Value(NaslValue::Number(x))) => Duration::from_secs(*x as u64),
            _ => Duration::from_secs(0),
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                let channel = match &session.channel {
                    Some(c) => c,
                    _ => {
                        return Ok(NaslValue::Null);
                    }
                };

                if channel.is_closed() {
                    return Err(FunctionErrorKind::Dirty(format!(
                        "Session ID {} not found",
                        session_id
                    )));
                }

                let mut response = String::new();
                if timeout.as_secs() > 0 {
                    if read_ssh_blocking(channel, timeout, &mut response) != 0 {
                        return Ok(NaslValue::Null);
                    }
                } else if read_ssh_nonblocking(channel, &mut response) != 0 {
                    return Ok(NaslValue::Null);
                }

                Ok(NaslValue::String(response))
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Write string to ssh shell.
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// nasl named params
    ///
    /// - cmd: A string to write to shell.
    ///
    /// return An integer: 0 on success, -1 on failure.
    fn nasl_ssh_shell_write<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let binding;
        let cmd = match register.named("cmd") {
            Some(ContextType::Value(NaslValue::String(x))) => x,
            Some(ContextType::Value(NaslValue::Data(x))) => {
                binding = x.iter().map(|x| *x as char).collect::<String>();
                &binding
            }
            _ => return Err(FunctionErrorKind::from("cmd")),
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                let channel = match &session.channel {
                    Some(c) => c,
                    _ => {
                        return Ok(NaslValue::Null);
                    }
                };

                if channel.is_closed() {
                    return Err(FunctionErrorKind::Dirty(format!(
                        "Session ID {} not found",
                        session_id
                    )));
                }

                match channel.stdin().write_all(cmd.as_bytes()) {
                    Ok(_) => Ok(NaslValue::Number(0)),
                    Err(_) => Ok(NaslValue::Number(-1)),
                }
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Close an ssh shell.
    ///
    /// nasl params
    /// - An SSH session id.
    fn nasl_ssh_shell_close<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                let _ = &session
                    .channel
                    .as_mut()
                    .map_or((), |c| c.close().unwrap_or(()));

                session.channel = None;
                Ok(NaslValue::Null)
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Authenticate a user on an ssh connection
    ///  
    /// The function starts the authentication process and pauses it when
    /// it finds the first non-echo prompt. The function expects the session
    /// id as its first unnamed argument.
    /// The first time this function is called for a session id, the named
    /// argument "login" is also expected.
    ///  
    /// nasl params
    ///  
    /// - An SSH session id.
    ///  
    /// nasl named params
    ///  
    /// - login: A string with the login name.
    ///  
    /// return A data block on success or NULL on error.
    fn nasl_ssh_login_interactive<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let login = match register.named("login") {
            Some(ContextType::Value(NaslValue::String(x))) => Some(x.to_owned()),
            _ => return Err(FunctionErrorKind::from("login")),
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                if !session.user_set {
                    set_opt_user(session, login, session_id)?;
                }
                let verbose = session.verbose > 0;

                // Get the authentication methods only once per session.
                let methods: AuthMethods = {
                    if !session.authmethods_valid {
                        get_authmethods(session, session_id, ctx.logger())?
                    } else {
                        session.authmethods
                    }
                };
                if verbose {
                    ctx.logger()
                        .info(&format!("Available methods:\n{:?}", methods));
                }
                if methods.contains(AuthMethods::INTERACTIVE) {
                    let mut prompt = String::new();
                    loop {
                        match session.session.userauth_keyboard_interactive(None, None) {
                            Ok(AuthStatus::Info) => {
                                let info =
                                    match session.session.userauth_keyboard_interactive_info() {
                                        Ok(i) => i,
                                        Err(_) => {
                                            return Err(FunctionErrorKind::Dirty(format!(
                                            "Failed setting user authentication for SessionID {}",
                                            session_id
                                        )));
                                        }
                                    };
                                if verbose {
                                    ctx.logger().info(&format!("SSH kbdint name={}", info.name));
                                    ctx.logger().info(&format!(
                                        "SSH kbdint instruction{}",
                                        info.instruction
                                    ));
                                }

                                for p in info.prompts.into_iter() {
                                    if !p.echo {
                                        prompt = p.prompt;
                                    }
                                }
                                break;
                            }
                            Ok(_) => {
                                if verbose {
                                    ctx.logger().info(&format!(
                                    "SSH keyboard-interactive authentication failed for session {}",
                                    session_id));
                                };
                                continue;
                            }
                            Err(_) => {
                                return Err(FunctionErrorKind::Dirty(format!(
                                    "Failed setting user authentication for SessionID {}",
                                    session_id
                                )));
                            }
                        }
                    }
                    return Ok(NaslValue::String(prompt));
                }
                Ok(NaslValue::Null)
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Authenticate a user on an ssh connection
    ///
    /// The function finishes the authentication process started by
    /// ssh_login_interactive. The function expects the session id as its first
    /// unnamed argument.
    ///
    /// To finish the password, the named argument "password" must contain
    /// a password.
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// nasl named params
    ///
    /// - password: A string with the password.
    ///
    /// return An integer as status value; 0 indicates success.
    ///
    fn nasl_ssh_login_interactive_pass<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let password = match register.named("pass") {
            Some(ContextType::Value(NaslValue::String(x))) => x,
            _ => return Err(FunctionErrorKind::from("pass")),
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                let verbose = session.verbose > 0;
                let info = match session.session.userauth_keyboard_interactive_info() {
                    Ok(i) => i,
                    Err(_) => {
                        return Err(FunctionErrorKind::Diagnostic(
                            format!(
                                "Failed setting user authentication for SessionID {}",
                                session_id
                            ),
                            Some(NaslValue::Number(-1)),
                        ));
                    }
                };

                if verbose {
                    ctx.logger().info(&format!("SSH kbdint name={}", info.name));
                    ctx.logger()
                        .info(&format!("SSH kbdint instruction{}", info.instruction));
                }

                let mut answers: Vec<String> = Vec::new();
                for p in info.prompts.into_iter() {
                    if !p.echo {
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
                        // Once set the answers we need to get info again to finish the auth process
                        loop {
                            match session.session.userauth_keyboard_interactive(None, None) {
                                Ok(AuthStatus::Info) => {
                                    session
                                        .session
                                        .userauth_keyboard_interactive_info()
                                        .unwrap();
                                    continue;
                                }
                                Ok(AuthStatus::Success) => break,
                                _ => {
                                    return Err(FunctionErrorKind::Diagnostic(
                                        format!("Session ID {} not found", session_id),
                                        Some(NaslValue::Number(-1)),
                                    ));
                                }
                            }
                        }
                        Ok(NaslValue::Number(0))
                    }

                    Err(e) => Err(FunctionErrorKind::Diagnostic(
                        format!("Not possible to set answers during authentication: {}", e),
                        Some(NaslValue::Number(-1)),
                    )),
                }
            }
            _ => Err(FunctionErrorKind::Diagnostic(
                format!("Session ID {} not found", session_id),
                Some(NaslValue::Number(-1)),
            )),
        }
    }

    /// Get the issue banner
    ///
    /// The function returns a string with the issue banner.  This is
    /// usually displayed before authentication.
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// return A data block on success or NULL on error.
    ///
    fn nasl_ssh_get_issue_banner<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                if !session.user_set {
                    //TODO: set the login with set_opt_user(). Get the user from the kb
                    return Ok(NaslValue::Null);
                }

                if !session.authmethods_valid {
                    get_authmethods(session, session_id, ctx.logger())?;
                }

                match session.session.get_issue_banner() {
                    Ok(b) => Ok(NaslValue::String(b)),
                    Err(_) => Ok(NaslValue::Null),
                }
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Get the server banner
    ///
    /// The function returns a string with the server banner.  This is
    /// usually the first data sent by the server.
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// return A data block on success or NULL on error.
    fn nasl_ssh_get_server_banner<K>(
        &self,
        register: &Register,
        _: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            // TODO: Check with openvas-nasl why the outputs doesn't match
            Some((_i, session)) => match session.session.get_server_banner() {
                Ok(b) => Ok(NaslValue::String(b)),
                Err(_) => Ok(NaslValue::Null),
            },
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Get the list of authmethods
    ///
    /// The function returns a string with comma separated authentication
    /// methods.  This is basically the same as returned by
    /// SSH_MSG_USERAUTH_FAILURE protocol element; however, it has been
    /// screened and put into a definitive order.
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// return A string on success or NULL on error.
    fn nasl_ssh_get_auth_methods<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                if !session.user_set {
                    //TODO: set the login with set_opt_user(). Get the user from the kb
                    return Ok(NaslValue::Null);
                }

                if !session.authmethods_valid {
                    get_authmethods(session, session_id, ctx.logger())?;
                };

                let mut methods = vec![];
                if session.authmethods.contains(AuthMethods::NONE) {
                    methods.push("none");
                }
                if session.authmethods.contains(AuthMethods::PASSWORD) {
                    methods.push("password");
                }
                if session.authmethods.contains(AuthMethods::PUBLIC_KEY) {
                    methods.push("publickey");
                }
                if session.authmethods.contains(AuthMethods::HOST_BASED) {
                    methods.push("hostbased");
                }
                if session.authmethods.contains(AuthMethods::INTERACTIVE) {
                    methods.push("keyboard-interactive");
                }

                if methods.is_empty() {
                    return Ok(NaslValue::Null);
                }
                Ok(NaslValue::String(methods.join(",")))
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Get the host key
    ///
    /// The function returns a string with the MD5 host key.
    ///
    /// @nasl params
    ///
    /// - An SSH session id.
    ///
    /// @naslret A data block on success or NULL on error.
    fn nasl_ssh_get_host_key<K>(
        &self,
        register: &Register,
        _: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => match session.session.get_server_public_key() {
                Ok(s) => match s.get_public_key_hash_hexa(libssh_rs::PublicKeyHashType::Md5) {
                    Ok(hash) => Ok(NaslValue::String(hash)),
                    Err(_) => Ok(NaslValue::Null),
                },
                Err(_) => Err(FunctionErrorKind::Diagnostic(
                    "Not possible to get the public key".to_string(),
                    Some(NaslValue::Null),
                )),
            },
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// Check if the SFTP subsystem is enabled on the remote SSH server.
    ///
    /// nasl params
    ///
    /// - An SSH session id.
    ///
    /// return An integer: 0 on success, -1 (SSH_ERROR) on Channel request
    /// subsystem failure. Greater than 0 means an error during SFTP init. NULL
    /// indicates a failure during session id verification.
    fn nasl_sftp_enabled_check<K>(
        &self,
        register: &Register,
        ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                let verbose = session.verbose > 0;
                match session.session.sftp() {
                    Ok(_) => Ok(NaslValue::Number(0)),
                    Err(e) => {
                        if verbose {
                            ctx.logger()
                                .info(&format!("SFTP enabled check error: {}", e));
                        }
                        Ok(NaslValue::Number(1))
                    }
                }
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    /// NASL NETCONF
    ///

    /// Execute the NETCONF subsystem on the the ssh channel
    ///
    /// nasluparam
    /// - An SSH session id.
    /// naslret An int on success or NULL on error.
    ///
    /// param[in] lexic Lexical context of NASL interpreter.
    /// return Session ID on success, NULL on failure.
    fn nasl_ssh_execute_netconf_subsystem<K>(
        &self,
        register: &Register,
        _ctx: &Context<K>,
    ) -> Result<NaslValue, FunctionErrorKind> {
        let positional = register.positional();
        if positional.is_empty() {
            return Err(FunctionErrorKind::MissingPositionalArguments {
                expected: 0,
                got: 1,
            });
        }

        let session_id = match &positional[0] {
            NaslValue::Number(x) => *x as i32,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    ("Invalid session ID").to_string(),
                ))
            }
        };

        let mut sessions = lock_sessions(&self.sessions)?;
        match sessions
            .iter_mut()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((_i, session)) => {
                // new channel
                let channel = match session.session.new_channel() {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(FunctionErrorKind::Dirty(format!(
                            "Failed to open a new channel for session ID {}: {}",
                            session.session_id, e
                        )));
                    }
                };

                match channel.open_session() {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(FunctionErrorKind::Dirty(format!(
                            "Channel failed to open session for session ID {}: {}",
                            session.session_id, e
                        )));
                    }
                };

                match channel.request_subsystem("netconf") {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(FunctionErrorKind::Dirty(format!(
                            "Channel failed to execyte NETCONF subsystem for session ID {}: {}",
                            session.session_id, e
                        )));
                    }
                };

                session.channel = Some(channel);
                Ok(NaslValue::Number(session_id as i64))
            }
            _ => Err(FunctionErrorKind::Dirty(format!(
                "Session ID {} not found",
                session_id
            ))),
        }
    }

    fn lookup<K>(key: &str) -> Option<NaslSSHFunction<K>> {
        match key {
            "ssh_connect" => Some(Ssh::nasl_ssh_connect),
            "ssh_disconnect" => Some(Ssh::nasl_ssh_disconnect),
            "ssh_session_id_from_sock" => Some(Ssh::nasl_ssh_session_id_from_sock),
            "ssh_get_sock" => Some(Ssh::nasl_ssh_get_sock),
            "ssh_set_login" => Some(Ssh::nasl_ssh_set_login),
            "ssh_userauth" => Some(Ssh::nasl_ssh_userauth),
            "ssh_request_exec" => Some(Ssh::nasl_ssh_request_exec),
            "ssh_shell_open" => Some(Ssh::nasl_ssh_shell_open),
            "ssh_shell_read" => Some(Ssh::nasl_ssh_shell_read),
            "ssh_shell_write" => Some(Ssh::nasl_ssh_shell_write),
            "ssh_shell_close" => Some(Ssh::nasl_ssh_shell_close),
            "ssh_login_interactive" => Some(Ssh::nasl_ssh_login_interactive),
            "ssh_login_interactive_pass" => Some(Ssh::nasl_ssh_login_interactive_pass),
            "ssh_get_issue_banner" => Some(Ssh::nasl_ssh_get_issue_banner),
            "ssh_get_server_banner" => Some(Ssh::nasl_ssh_get_server_banner),
            "ssh_get_auth_methods" => Some(Ssh::nasl_ssh_get_auth_methods),
            "ssh_get_host_key" => Some(Ssh::nasl_ssh_get_host_key),
            "sftp_enabled_check" => Some(Ssh::nasl_sftp_enabled_check),
            "ssh_execute_netconf_subsystem" => Some(Ssh::nasl_ssh_execute_netconf_subsystem),
            _ => None,
        }
    }
}

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for Ssh {
    fn nasl_fn_cache_clear(&self) -> Option<usize> {
        let mut data = Arc::as_ref(&self.sessions).lock().unwrap();
        if data.is_empty() {
            return None;
        }
        let result = data.len();
        data.clear();
        data.shrink_to_fit();
        Some(result)
    }

    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        Ssh::lookup(name).map(|f| f(self, register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        Ssh::lookup::<K>(name).is_some()
    }
}
