// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use dns_lookup::lookup_addr;

use crate::function_set;
use crate::nasl::utils::{error::FunctionErrorKind, lookup_keys::TARGET};

use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::{Context, ContextType, Register};

/// Resolves IP address of target to hostname
///
/// It does lookup TARGET and when not found falls back to 127.0.0.1 to resolve.
/// If the TARGET is not a IP address than we assume that it already is a fqdn or a hostname and will return that instead.
fn resolve_hostname(register: &Register) -> Result<String, FunctionErrorKind> {
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

/// Return the target's IP address as IpAddr.
pub fn get_host_ip(context: &Context) -> Result<IpAddr, FunctionErrorKind> {
    let default_ip = "127.0.0.1";
    let r_sock_addr = match context.target() {
        x if !x.is_empty() => IpAddr::from_str(x),
        _ => IpAddr::from_str(default_ip),
    };

    match r_sock_addr {
        Ok(x) => Ok(x),
        Err(e) => Err(FunctionErrorKind::wrong_unnamed_argument(
            "IP address",
            e.to_string().as_str(),
        )),
    }
}

/// Return the target's IP address or 127.0.0.1 if not set.
fn nasl_get_host_ip(
    _register: &Register,
    context: &Context,
) -> Result<NaslValue, FunctionErrorKind> {
    let ip = get_host_ip(context)?;
    Ok(NaslValue::String(ip.to_string()))
}

fn resolve(
    mut hostname: String,
) -> Result<Option<Box<dyn Iterator<Item = SocketAddr>>>, FunctionErrorKind> {
    //std::net to_socket_addrs() requires a port. Therefore, using a dummy port
    hostname.push_str(":5000");

    match hostname.to_socket_addrs() {
        Ok(addr) => Ok(Some(Box::new(addr))),
        // assumes that target is already a hostname
        Err(_) => Err(FunctionErrorKind::diagnostic_ret_null("Missing Hostname")),
    }
}

/// Get an IP address corresponding to the host name
fn resolve_host_name(
    register: &Register,
    _context: &Context,
) -> Result<NaslValue, FunctionErrorKind> {
    let hostname = match register.named("hostname") {
        Some(ContextType::Value(NaslValue::String(x))) if !x.is_empty() => x.clone(),
        _ => {
            return Err(FunctionErrorKind::diagnostic_ret_null("Missing Hostname"));
        }
    };

    match resolve(hostname)? {
        Some(mut a) => {
            let address = a.next().map_or_else(String::new, |x| x.to_string());
            let address = &address[..(address.len() - 5)];
            Ok(NaslValue::String(address.to_string()))
        }
        None => Ok(NaslValue::Null),
    }
}
/// Resolve a hostname to all found addresses and return them in an NaslValue::Array
fn resolve_hostname_to_multiple_ips(
    register: &Register,
    _context: &Context,
) -> Result<NaslValue, FunctionErrorKind> {
    let hostname = match register.named("hostname") {
        Some(ContextType::Value(NaslValue::String(x))) if !x.is_empty() => x.clone(),
        _ => {
            return Err(FunctionErrorKind::diagnostic_ret_null("Missing Hostname"));
        }
    };

    match resolve(hostname)? {
        Some(addr) => {
            let ips = addr
                .into_iter()
                .map(|x| {
                    let address = x.to_string();
                    let address = &address[..(address.len() - 5)];
                    NaslValue::String(address.to_string())
                })
                .collect();
            Ok(NaslValue::Array(ips))
        }
        // assumes that target is already a hostname
        None => Ok(NaslValue::Null),
    }
}

/// Check if the currently scanned target is an IPv6 address.
/// Return TRUE if the current target is an IPv6 address, else FALSE. In case of an error, NULL is returned.
fn target_is_ipv6(_register: &Register, context: &Context) -> Result<NaslValue, FunctionErrorKind> {
    let target_ori = match context.target().is_empty() {
        true => {
            return Err(FunctionErrorKind::diagnostic_ret_null("Address is NULL!"));
        }
        false => context.target(),
    };

    let mut target = target_ori.to_string();
    // IPV6 must be between []
    if target.contains(":") {
        let mut t_aux = String::from("[");
        t_aux.push_str(target_ori);
        t_aux.push(']');
        target = t_aux;
    }

    // SocketAddr requires a socket, not only the IP addr.
    target.push_str(":5000");
    match target.to_socket_addrs() {
        Ok(addr) => {
            let v = addr.into_iter().filter(|x| x.is_ipv6()).collect::<Vec<_>>();
            Ok(NaslValue::Boolean(!v.is_empty()))
        }
        Err(_) => Err(FunctionErrorKind::diagnostic_ret_null("address is Null")),
    }
}

fn same_host(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.len() != 2 {
        return Err(FunctionErrorKind::diagnostic_ret_null(
            "same_host needs two parameters!",
        ));
    }

    let h1 = match &positional[0] {
        NaslValue::String(x) => {
            if let Some(h) = resolve(x.to_string())? {
                h
            } else {
                return Err(FunctionErrorKind::diagnostic_ret_null(
                    "Wrong parameter type",
                ));
            }
        }
        _ => {
            return Err(FunctionErrorKind::diagnostic_ret_null(
                "Wrong parameter type",
            ));
        }
    };

    let h2 = match &positional[1] {
        NaslValue::String(x) => {
            if let Some(h) = resolve(x.to_string())? {
                h
            } else {
                return Err(FunctionErrorKind::diagnostic_ret_null(
                    "Wrong parameter type",
                ));
            }
        }
        _ => {
            return Err(FunctionErrorKind::diagnostic_ret_null(
                "Wrong parameter type",
            ));
        }
    };

    let cmp_hostname = match register.named("cmp_hostname") {
        Some(ContextType::Value(NaslValue::Boolean(x))) => *x,
        _ => false,
    };

    let addr1: Vec<IpAddr> = h1.into_iter().map(|x| x.ip()).collect::<Vec<_>>();
    let addr2: Vec<IpAddr> = h2.into_iter().map(|x| x.ip()).collect::<Vec<_>>();

    let hostnames1 = addr1
        .clone()
        .into_iter()
        .map(|x| lookup_addr(&x))
        .collect::<Vec<_>>();
    let hostnames2 = addr2
        .clone()
        .into_iter()
        .map(|x| lookup_addr(&x))
        .collect::<Vec<_>>();

    let mut flag = false;
    for a1 in addr1.iter() {
        for a2 in addr2.iter() {
            if a1.eq(a2) {
                flag = true;
            }
        }
    }

    if cmp_hostname {
        for hn1 in hostnames1.iter() {
            for hn2 in hostnames2.iter() {
                if hn1.is_ok() && hn2.is_ok() && hn1.as_ref().unwrap() == hn2.as_ref().unwrap() {
                    flag = true;
                }
            }
        }
    }

    if flag {
        Ok(NaslValue::Boolean(true))
    } else {
        Ok(NaslValue::Boolean(false))
    }
}

pub struct Host;

function_set! {
    Host,
    sync_stateless,
    (
        get_host_name,
        get_host_names,
        (nasl_get_host_ip, "get_host_ip"),
        resolve_host_name,
        resolve_hostname_to_multiple_ips,
        (target_is_ipv6, "TARGET_IS_IPV6"),
        same_host
    )
}
