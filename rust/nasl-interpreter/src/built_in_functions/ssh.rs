// Copyright (C) 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL ssh and sftp functions

use std::time::Duration;
use crate::{
    error::{FunctionError, FunctionErrorKind},
    lookup_keys::TARGET, Context, ContextType,
    NaslFunction, NaslValue, Register,
    nasl_ssh,
};

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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let sock = match register.named("socket") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x,
        _ => 0i64,
    };

    let port = if sock > 0 {
        match register.named("port") {
            Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
            _ => 0u16, // TODO: implement get_ssh_port()
        }
    } else {
        0u16
    };

    let ip_str = match register.named(TARGET) {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ => "127.0.0.1",
    };

    let timeout = match register.named("timeout") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x,
        _ => 0i64,
    };

    let key_type = match register.named("keytype") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        _ => String::new(),
    };

    let csciphers = match register.named("csciphers") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        _ => String::new(),
    };

    let scciphers = match register.named("scciphers") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        _ => String::new(),
    };

    nasl_ssh::connect(
        sock, ip_str, port, timeout, &key_type, &csciphers, &scciphers, ctx,
    )?;

    Ok(NaslValue::Null)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_disconnect",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    match &positional[0] {
        NaslValue::Number(x) => nasl_ssh::disconnect(*x as i32, ctx),
        _ => Err(FunctionError::new(
            "nasl_ssh_disconnect",
            FunctionErrorKind::WrongArgument(("Invalid Session ID").to_string()))),
    }
}

/// Given a socket, return the corresponding session id.
/// nasl params
/// - A NASL socket value
///
/// return An integer with the corresponding ssh session id or 0 if
///          no session id is known for the given socket.
fn nasl_ssh_session_id_from_sock<K>(
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {

    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_session_if_from_sock",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    match &positional[0] {
        NaslValue::Number(x) => nasl_ssh::session_id_from_sock(*x as i32, ctx),
        _ => Err(FunctionError::new(
            "nasl_ssh_session_id_from_sock",
            FunctionErrorKind::WrongArgument(("Invalid socket FD").to_string()))),
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {

    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_get_sock",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    match &positional[0] {
        NaslValue::Number(x) => nasl_ssh::get_sock(*x as i32, ctx),
        _ => Err(FunctionError::new(
            "nasl_ssh_get_sock",
            FunctionErrorKind::WrongArgument(("Invalid session ID").to_string()))),
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {

    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_set_login",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_set_login",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let login = match register.named("login") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_set_login",
                FunctionErrorKind::from("login")))
        },
    };

    nasl_ssh::set_login(sid, login, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
 
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_userauth",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_userauth",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let login = match register.named("login") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_userauth",
                FunctionErrorKind::from("login")))
        },
    };

    let password = match register.named("password") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        _ => String::new(),
    };

    let privatekey = match register.named("privatekey") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        _ => String::new(),
    };
    let passphrase = match register.named("passphrase") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        _ => String::new(),
    };

    if password.is_empty() && privatekey.is_empty() && passphrase.is_empty() {
        //TODO: Get values from KB
    }

    nasl_ssh::userauth(sid, login, &password, &privatekey, &passphrase, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
     let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_request_exec",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_request_exec",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let cmd = match register.named("cmd") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_request_exec",
                FunctionErrorKind::from("cmd")))
        },
    };

    let stdout = match register.named("stdout ") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_request_exec",
                FunctionErrorKind::from("stdout")))
        },
    };
    
    let stderr = match register.named("stderr") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_request_exec",
                FunctionErrorKind::from("stderr")))
        },
    };

    nasl_ssh::request_exec(sid, cmd, stdout, stderr, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_shell_open",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_shell_open",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let pty = match register.named("pty") {
        Some(ContextType::Value(NaslValue::Boolean(x))) => *x,
        _ => false
    };

    nasl_ssh::shell_open(sid, pty, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
     let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_shell_read",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_shell_read",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let timeout = match register.named("timeout") {
        Some(ContextType::Value(NaslValue::Number(x))) => Duration::from_secs(*x as u64),
        _ => Duration::from_secs(0),
    };

    nasl_ssh::shell_read(sid, timeout, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
     let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_shell_write",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_shell_write",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let cmd = match register.named("cmd") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_shell_write",
                FunctionErrorKind::from("cmd")))
        },
    };

    nasl_ssh::shell_write(sid, cmd, ctx)
}


/// Close an ssh shell.
///
/// nasl params
/// - An SSH session id.
fn nasl_ssh_shell_close<K>(
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_shell_close",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_shell_close",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };

    nasl_ssh::shell_close(sid, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_login_interactive",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_login_interactive",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let login = match register.named("login") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_login_interactive",
                FunctionErrorKind::from("login")))
        },
    };

    nasl_ssh::login_interactive(sid, login, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_login_interactive_pass",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_login_interactive_pass",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    
    let pass = match register.named("pass") {
        Some(ContextType::Value(NaslValue::String(x))) => x,
        _ =>{
            return Err(FunctionError::new(
                "nasl_ssh_login_interactive_pass",
                FunctionErrorKind::from("pass")))
        },
    };
    nasl_ssh::login_interactive_pass(sid, pass, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_get_issue_banner",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_get_issue_banner",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    nasl_ssh::get_issue_banner(sid, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_get_server_banner",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_get_server_banner",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    nasl_ssh::get_server_banner(sid, ctx)
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_get_auth_methods",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_get_auth_methods",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    nasl_ssh::get_auth_methods(sid, ctx) 
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_get_server_banner",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_get_server_banner",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    nasl_ssh::get_host_key(sid, ctx) 
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
    register: &Register,
    ctx: &Context<K>
) -> Result<NaslValue, FunctionError> {
    let positional = register.positional();
       if positional.is_empty() {
        return Err(FunctionError::new(
            "nasl_ssh_get_server_banner",
            FunctionErrorKind::MissingPositionalArguments{expected: 0, got: 1}));
       }

    let sid = match &positional[0] {
        NaslValue::Number(x) => *x as i32,
        _ => {
            return Err(FunctionError::new(
                "nasl_ssh_get_server_banner",
                FunctionErrorKind::WrongArgument(("Invalid session ID").to_string())))},
    };
    nasl_ssh::sftp_enabled_check(sid, ctx) 
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>>{
    match key {
        "ssh_connect" => Some(nasl_ssh_connect),
        "ssh_disconnect" => Some(nasl_ssh_disconnect),
        "ssh_session_id_from_sock" => Some(nasl_ssh_session_id_from_sock),
        "ssh_get_sock" => Some(nasl_ssh_get_sock),
        "ssh_set_login" => Some(nasl_ssh_set_login),
        "ssh_userauth" => Some(nasl_ssh_userauth),
        "ssh_request_exec" => Some(nasl_ssh_request_exec),
        "ssh_shell_open" => Some(nasl_ssh_shell_open),
        "ssh_shell_read" => Some(nasl_ssh_shell_read),
        "ssh_shell_write" => Some(nasl_ssh_shell_write),
        "ssh_shell_close" => Some(nasl_ssh_shell_close),
        "ssh_login_interactive" => Some(nasl_ssh_login_interactive),
        "ssh_login_interactive_pass" => Some(nasl_ssh_login_interactive_pass),
        "ssh_get_issue_banner" => Some(nasl_ssh_get_issue_banner),
        "ssh_get_server_banner" => Some(nasl_ssh_get_server_banner),
        "ssh_get_auth_methods" => Some(nasl_ssh_get_auth_methods),
        "ssh_get_host_key" => Some(nasl_ssh_get_host_key),
        "sftp_enabled_check" => Some(nasl_sftp_enabled_check),
        _ => None,
    }
}
