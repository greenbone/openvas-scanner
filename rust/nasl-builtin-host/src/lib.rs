// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{net::IpAddr, str, str::FromStr};

use nasl_builtin_utils::{error::FunctionErrorKind, lookup_keys::TARGET};

use nasl_builtin_utils::{Context, ContextType, NaslFunction, Register};
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
fn get_host_names<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    resolve_hostname(register).map(|x| NaslValue::Array(vec![NaslValue::String(x)]))
}

/// NASL function to get the current hostname
///
/// As of now (2023-01-20) there is no vhost handling.
/// Therefore this function does load the registered TARGET and if it is an IP Address resolves it via DNS instead.
fn get_host_name<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    resolve_hostname(register).map(NaslValue::String)
}

/// Return the target's IP address as IpAddr.
pub fn get_host_ip<K>(context: &Context<K>) -> Result<IpAddr, FunctionErrorKind> {
    let default_ip = "127.0.0.1";
    let r_sock_addr = match context.target() {
        x if !x.is_empty() => IpAddr::from_str(x),
        _ => IpAddr::from_str(default_ip),
    };

    match r_sock_addr {
        Ok(x) => Ok(x),
        Err(e) => Err(("IP address", e.to_string().as_str()).into()),
    }
}

/// Return the target's IP address or 127.0.0.1 if not set.
fn nasl_get_host_ip<K>(
    _register: &Register,
    context: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let ip = get_host_ip(context)?;
    Ok(NaslValue::String(ip.to_string()))
}

/// Returns found function for key or None when not found
fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "get_host_name" => Some(get_host_name),
        "get_host_names" => Some(get_host_names),
        "get_host_ip" => Some(nasl_get_host_ip),
        _ => None,
    }
}

/// The description builtin function
pub struct Host;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for Host {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup::<K>(name).is_some()
    }
}
