// Copyright (C) 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines functions and structures for handling ssh connections

use libssh_rs::{LogLevel, Session, SshOption};

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::{env, time::Duration};

use crate::{
    error::{FunctionError, FunctionErrorKind},
    Context, NaslValue,
    nasl_sessions::*,
};
/// Max open session for host
const SESSION_TABLE_SIZE: usize = 10;

/// Stores all open sessions.
pub struct SshSessionTable {
    sessions: Vec<Box<dyn SshSessionHandler>>,
}

impl<S> SessionTableHandler<S> for SshSessionTable
where
    S: SshSessionHandler + 'static,
{
    
    fn add_session(&mut self, s: S) -> Option<usize> {
        self.sessions.push(Box::new(s));
        Some(self.sessions.len() - 1)
    }    
   
    fn del_session(&self, _session: i32) -> Option<()> {
        Some(())
    }

    fn get_session_by_position(&self, _pos: usize) -> Option<&S> {
        //self.sessions[pos]
        None
    }
}


impl SshSessionTable {
    fn new() -> SessionTable {
        SessionTable::Ssh(
            SshSessionTable { 
                sessions: vec![],
            }
        )
    }
    
    //fn get_session_by_position(&self, pos: usize) -> Option<&SshSession> {
    //    self.sessions[pos]
    //}

    //fn get_session_by_id(&self, id: i32) -> Option<&SshSession> {
    //    for s in self.sessions.iter() {
    //        let session = match s {
    //            Some(session) => {
    //                if *session.session_id == id {
    //                    Some(*session)
    //                } else {
    //                    None
    //                }
    //            }
    //            None => None,
    //        };
    //        if session.is_some() {
    //            return session;
    //        }
    //    }
    //    None
    //}
}

pub struct SshSession {
    session: Session,
    authmethods_valid: i64,
    user_set: i64,
    verbose: i32,
    session_id: i32,
}

pub trait SshSessionHandler {
    fn new(
        &self,
        session: Session,
        authmethods_valid: i64,
        user_set: i64,
        verbose: i32,
        session_id: i32,
    ) -> SshSession;
}

impl SshSessionHandler for SshSession {
    fn new(
        &self,
        session: Session,
        authmethods_valid: i64,
        user_set: i64,
        verbose: i32,
        session_id: i32,
    ) -> Self {
        Self {
            session,
            authmethods_valid,
            user_set,
            verbose,
            session_id,
        }
    }
}

//impl SshSession {
//    pub fn new(
//        session: Session,
//        authmethods_valid: i64,
//        user_set: i64,
//        verbose: i32,
//        session_id: i32,
//    ) -> Self {
//        Self {
//            session,
//            authmethods_valid,
//            user_set,
//            verbose,
//            session_id,
//        }
//    }
//}



/// Establish an ssh session to the host.
pub fn connect<K>(
    sock: i64,
    ip_str: &str,
    port: u16,
    timeout: i64,
    key_type: &str,
    csciphers: &str,
    scciphers: &str,
    ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    let mut session = match Session::new() {
        Ok(s) => s,
        Err(e) => {
            return Err(FunctionError{
                function: "connect".to_string(),
                kind: FunctionErrorKind::Diagnostic(
                    format!(
                        "Function called from {}: Failed to set the SSH connection timeout to {} seconds: {}", "func", timeout, e),
                    Some(NaslValue::Null)
                )
            }); // TODO: get_nasl_function_name() and oid/key
        }
    };

    let option = libssh_rs::SshOption::Timeout(Duration::from_secs(timeout as u64));
    match Session::set_option(&session, option) {
        Ok(_) => (),
        Err(e) => {
            return Err(FunctionError{
                function: "connect".to_string(),
                kind: FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} called from {}: Failed to set the SSH connection timeout to {} seconds: {}", "func", "key", timeout, e),
                    Some(NaslValue::Null)
                )
            });
        }
    };

    let mut verbose = env::var("OPENVAS_LIBSSH_DEBUG")
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
    match Session::set_option(&session, option) {
        Ok(_) => (),
        Err(_) => return Ok(NaslValue::Null),
    };

    let option = libssh_rs::SshOption::BindAddress(ip_str.to_string());
    match Session::set_option(&session, option) {
        Ok(_) => (),
        Err(e) => {
            return Err(FunctionError{
                function: "connect".to_string(),
                kind: FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} (calling internal function {}): Failed to set SSH hostname '{}': {}", "func", "nasl_ssh_connect", ip_str, e),
                    Some(NaslValue::Null)
                )
            });
        }
    };

    let option = libssh_rs::SshOption::KnownHosts(Some("/dev/null".to_string()));
    match Session::set_option(&session, option) {
        Ok(_) => (),
        Err(e) => {
            return Err(FunctionError{
                function: "connect".to_string(),
                kind: FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} (calling internal function {}): Failed to disable known_hosts: {}","func", "nasl_ssh_connect", e), // TODO: get_nasl_function_name()
                    Some(NaslValue::Null)
                )
            });
        }
    };

    if !key_type.is_empty() {
        let option = libssh_rs::SshOption::PublicKeyAcceptedTypes(key_type.to_string());
        match Session::set_option(&session, option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionError{
                function: "connect".to_string(),
                kind: FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} (calling internal function {}): Failed to set SSH key type '{}': {}", "func", "nasl_ssh_connect", key_type, e), // TODO: get_nasl_function_name()
                    Some(NaslValue::Null)
                )
            });
            }
        };
    }

    if !csciphers.is_empty() {
        let option = libssh_rs::SshOption::CiphersCS(csciphers.to_string());
        match Session::set_option(&session, option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionError{
                    function: "connect".to_string(),
                    kind: FunctionErrorKind::Diagnostic(
                        format!(
                            "Function {} (calling internal function {}): Failed to set SSH client to server ciphers '{}': {}", "func", "nasl_ssh_connect", csciphers, e), // TODO: get_nasl_function_name()
                        Some(NaslValue::Null)
                    )
                });
            }
        };
    }

    if !scciphers.is_empty() {
        let option = libssh_rs::SshOption::CiphersSC(scciphers.to_string());
        match Session::set_option(&session, option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionError{
                function: "connect".to_string(),
                kind: FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} (calling internal function {}): Failed to set SSH server to client ciphers '{}': {}", "func", "nasl_ssh_connect", scciphers, e), // TODO: get_nasl_function_name()
                    Some(NaslValue::Null)
                )
            });
            }
        };
    }

    let valid_ports = 1..65535;
    if valid_ports.contains(&port) {
        let option = libssh_rs::SshOption::Port(port);
        match Session::set_option(&session, option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionError{
                function: "connect".to_string(),
                kind: FunctionErrorKind::Diagnostic(
                    format!(
                        "Function {} (calling internal function {}) called from {}: Failed to set SSH port '{}': {}", "func", "nasl_ssh_connect", "key", port, e), // TODO: get_nasl_function_name()
                    Some(NaslValue::Null),
                )
            });
            }
        };
    }
    let mut forced_sock = -1;
    if sock > 0 {
        // This is a fake raw socket.
        // TODO: implement openvas_get_socket_from_connection()
        let my_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let option = libssh_rs::SshOption::Socket(my_sock.as_raw_fd());

        if verbose > 0 {
            ctx.logger().info(format!(
                "Setting SSH fd for '{}' to {} (NASL sock={}",
                ip_str,
                my_sock.as_raw_fd(),
                sock
            ));
        }

        match Session::set_option(&session, option) {
            Ok(_) => (),
            Err(e) => {
                return Err(FunctionError{
                    function: "connect".to_string(),
                    kind: FunctionErrorKind::Diagnostic(
                        format!(
                            "Function {} (calling internal function {}) called from {}: Failed to set SSH fd for '{}' to {} (NASL sock={}): {}", "func", "nasl_ssh_connect", "key", ip_str, my_sock.as_raw_fd(), sock, e), // TODO: get_nasl_function_name()
                        Some(NaslValue::Null),
                    )
                });
            }
        };
        forced_sock = sock; // TODO: check and fix everything related to open socket
    }
    let mut authmethods_valid: i64 = 0;
    let mut user_set: i64 = 0;
    let mut session_id = 9000; //TODO: implement next_session_id()
    let mut s = SshSession{
        session,
        authmethods_valid,
        user_set,
        verbose,
        session_id,
    };
    let mut st = SshSessionTable::new();
    ctx.sessions().add_table(st);
    //let pos = st.add_session(s);

    Ok(NaslValue::Null)
//    let se = match st.get_session_by_position(pos) {
//        Some(s) => s,
//        _ => return Ok(NaslValue::Null),
//    };
// 
//    if *se.verbose > 0 {
//        ctx.logger().info(format!(
//            "Connecting to SSH server '{}' (port {}, sock {})",
//            ip_str, port, sock
//        ));
//    }

//    match se.session.connect() {
//        Ok(_) => Ok(NaslValue::Number(session_id as i64)),
//        Err(e) => {
//            se.session.disconnect();
//            st.sessions[pos] = None;
//            Err(FunctionError {
//                function: "connect".to_string(),
//                kind: FunctionErrorKind::Diagnostic(
//                    format!(
//                        "Failed to connect to SSH server '{}' (port {}, sock {}, f={}): {}",
//                        ip_str, port, sock, forced_sock, e
//                    ),
//                    Some(NaslValue::Null),
//                ),
//            })
//        }
//    }
}

/// Closes an SSH Session and releases from the SessionTable
pub fn disconnect<K>(_sesion_id: i32, _ctx: &Context<K>) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Return the an SSH session ID given a sock FD
pub fn session_id_from_sock<K>(_sock: i32, _ctx: &Context<K>) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Given a session id, return the corresponding socket
pub fn get_sock<K>(_sesion_id: i32, _ctx: &Context<K>) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Set the login name for the authentication.
pub fn set_login<K>(
    _session_id: i32,
    _login: &str,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Authenticate a user on an ssh connection
pub fn userauth<K>(
    _session_id: i32,
    _login: &str,
    _password: &str,
    _privatekey: &str,
    _passphrase: &str,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Authenticate a user on an ssh connection
pub fn login_interactive<K>(
    _session_id: i32,
    _login: &str,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Authenticate a user on an ssh connection
pub fn login_interactive_pass<K>(
    _session_id: i32,
    _password: &str,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Run a command via ssh.
pub fn request_exec<K>(
    _session_id: i32,
    _cmd: &str,
    _stdout: i32,
    _stderr: i32,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Request an ssh shell
pub fn shell_open<K>(
    //session id, &login
    _session_id: i32,
    _pty: bool,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Read the output of an ssh shell.
pub fn shell_read<K>(
    _session_id: i32,
    _timeout: Duration,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}
/// Write string to ssh shell
pub fn shell_write<K>(
    _session_id: i32,
    _cmd: &str,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Close an ssh shell
pub fn shell_close<K>(_session_id: i32, _ctx: &Context<K>) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Get the issue banner
pub fn get_issue_banner<K>(
    //session id
    _session_id: i32,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Get the server banner
pub fn get_server_banner<K>(
    _session_id: i32,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Get the list of authmethods
pub fn get_auth_methods<K>(
    _session_id: i32,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Get the host key
pub fn get_host_key<K>(_session_id: i32, _ctx: &Context<K>) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}

/// Get the host key
pub fn sftp_enabled_check<K>(
    _session_id: i32,
    _ctx: &Context<K>,
) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Null)
}
