// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_builtin_utils::{error::FunctionErrorKind, lookup_keys::TARGET};

use nasl_builtin_utils::{function_set, Context, ContextType, Register};
use nasl_syntax::NaslValue;

/// Resolves IP address of target to hostname
///
/// It does lookup TARGET and when not found falls back to 127.0.0.1 to resolve.
/// If the TARGET is not a IP address than we assume that it already is a fqdn or a hostname and will return that instead.
fn resolve_hostname(register: &Register) -> Result<String, FunctionErrorKind> {
    use std::net::ToSocketAddrs;

    let default_ip = "127.0.0.1";
    // currently we use shadow variables as _FC_ANON_ARGS; the original openvas uses redis for that purpose.
    let target = register.named(TARGET).map_or_else(
        || default_ip.to_owned(),
        |x| match x {
            ContextType::Value(NaslValue::String(x)) => x.clone(),
            _ => default_ip.to_owned(),
        },
    );

    match target.to_socket_addrs() {
        Ok(mut addr) => Ok(addr.next().map_or_else(String::new, |x| x.to_string())),
        // assumes that target is already a hostname
        Err(_) => Ok(target),
    }
}

/// NASL function to get all stored vhosts
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Address resolves it via DNS instead.
fn get_host_names(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    resolve_hostname(register).map(|x| NaslValue::Array(vec![NaslValue::String(x)]))
}

/// NASL function to get the current hostname
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Address resolves it via DNS instead.
fn get_host_name(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    resolve_hostname(register).map(NaslValue::String)
}

pub struct Host;

function_set! {
    Host,
    sync_stateless,
    (
        get_host_name,
        get_host_names,
    )
}
