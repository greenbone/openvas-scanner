// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::{
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use dns_lookup::lookup_addr;
use thiserror::Error;

use crate::nasl::prelude::*;
use crate::nasl::utils::hosts::resolve;

#[derive(Debug, Error)]
pub enum HostError {
    #[error("Empty hostname.")]
    EmptyHostname,
    #[error("Empty address.")]
    EmptyAddress,
    #[error("Target is not a hostname.")]
    TargetIsNotAHostname,
}

struct Hostname(String);
impl<'a> FromNaslValue<'a> for Hostname {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FnError> {
        let str = String::from_nasl_value(value)?;
        if str.is_empty() {
            Err(HostError::EmptyHostname.into())
        } else {
            Ok(Self(str))
        }
    }
}

/// Get a list of found hostnames or a IP of the current target in case no hostnames were found yet.
#[nasl_function]
fn get_host_names(context: &Context) -> Result<NaslValue, FnError> {
    let hns = context.target_vhosts();
    if !hns.is_empty() {
        let hns = hns
            .into_iter()
            .map(|(h, _s)| NaslValue::String(h))
            .collect::<Vec<_>>();
        return Ok(NaslValue::Array(hns));
    };
    Ok(NaslValue::Array(vec![NaslValue::String(
        context.target().to_string(),
    )]))
}

/// Return the target's IP address as IpAddr.
pub fn get_host_ip(context: &Context) -> Result<IpAddr, FnError> {
    let default_ip = "127.0.0.1";
    let r_sock_addr = match context.target() {
        x if !x.is_empty() => IpAddr::from_str(x),
        _ => IpAddr::from_str(default_ip),
    };

    match r_sock_addr {
        Ok(x) => Ok(x),
        Err(e) => Err(FnError::wrong_unnamed_argument(
            "IP address",
            e.to_string().as_str(),
        )),
    }
}

///Expands the vHosts list with the given hostname.
///The mandatory parameter hostname is of type string. It contains the hostname which should be added to the list of vHosts
///Additionally a source, how the hostname was detected can be added with the named argument source as a string. If it is not given, the value NASL is set as default.
#[nasl_function(named(hostname, source))]
pub fn add_host_name(
    context: &Context,
    hostname: Hostname,
    source: Option<&str>,
) -> Result<NaslValue, FnError> {
    let source = source.filter(|x| !x.is_empty()).unwrap_or("NASL");
    context.add_hostname(hostname.0, source.into());
    Ok(NaslValue::Null)
}

/// Get the host name of the currently scanned target. If there is no host name available, the IP of the target is returned instead.
#[nasl_function]
pub fn get_host_name(_register: &Register, context: &Context) -> Result<NaslValue, FnError> {
    let vh = context.target_vhosts();
    let v = if !vh.is_empty() {
        vh.iter()
            .map(|(v, _s)| NaslValue::String(v.to_string()))
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    //TODO: store the current hostname being forked.
    //TODO: don't fork if expand_vhost is disabled.
    //TODO: don't fork if already in a vhost
    if !v.is_empty() {
        return Ok(NaslValue::Fork(v));
    }

    let host = match get_host_ip(context) {
        Ok(ip) => match lookup_addr(&ip) {
            Ok(host) => host,
            Err(_) => ip.to_string(),
        },
        Err(_) => context.target().to_string(),
    };
    Ok(NaslValue::String(host))
}

/// This function returns the source of detection of a given hostname.
/// The named parameter hostname is a string containing the hostname.
/// When no hostname is given, the current scanned host is taken.
/// If no virtual hosts are found yet this function always returns IP-address.
#[nasl_function(named(hostname))]
pub fn get_host_name_source(context: &Context, hostname: Hostname) -> String {
    let vh = context.target_vhosts();
    if !vh.is_empty() {
        if let Some((_, source)) = vh.into_iter().find(|(v, _)| v == &hostname.0) {
            return source;
        };
    }
    context.target().to_string()
}

/// Return the target's IP address or 127.0.0.1 if not set.
#[nasl_function]
fn nasl_get_host_ip(context: &Context) -> Result<NaslValue, FnError> {
    let ip = get_host_ip(context)?;
    Ok(NaslValue::String(ip.to_string()))
}

/// Get an IP address corresponding to the host name
#[nasl_function(named(hostname))]
fn resolve_host_name(hostname: Hostname) -> String {
    resolve(hostname.0).map_or_else(
        |_| "127.0.0.1".to_string(),
        |x| x.first().map_or("127.0.0.1".to_string(), |v| v.to_string()),
    )
}

/// Resolve a hostname to all found addresses and return them in an NaslValue::Array
#[nasl_function(named(hostname))]
fn resolve_hostname_to_multiple_ips(hostname: Hostname) -> Result<NaslValue, FnError> {
    let ips = resolve(hostname.0)?
        .into_iter()
        .map(|x| NaslValue::String(x.to_string()))
        .collect();
    Ok(NaslValue::Array(ips))
}

/// Check if the currently scanned target is an IPv6 address.
/// Return TRUE if the current target is an IPv6 address, else FALSE. In case of an error, NULL is returned.
#[nasl_function]
fn target_is_ipv6(context: &Context) -> Result<bool, FnError> {
    let target = match context.target().is_empty() {
        true => {
            return Err(HostError::EmptyAddress.into());
        }
        false => context.target(),
    };
    Ok(target.parse::<Ipv6Addr>().is_ok())
}

/// Compare if two hosts are the same.
/// The first two unnamed arguments are string containing the host to compare
/// If the named argument cmp_hostname is set to TRUE, the given hosts are resolved into their hostnames
#[nasl_function(named(cmp_hostname))]
fn same_host(h1: &str, h2: &str, cmp_hostname: Option<bool>) -> Result<bool, FnError> {
    let h1 = resolve(h1.to_string())?;
    let h2 = resolve(h2.to_string())?;

    let hostnames1 = h1
        .iter()
        .filter_map(|x| lookup_addr(x).ok())
        .collect::<Vec<_>>();
    let hostnames2 = h2
        .iter()
        .filter_map(|x| lookup_addr(x).ok())
        .collect::<Vec<_>>();

    let any_ip_address_matches = h1.iter().any(|a1| h2.contains(a1));
    let any_hostname_matches = hostnames1.iter().any(|h1| hostnames2.contains(h1));
    let cmp_hostname = cmp_hostname.filter(|x| *x).unwrap_or(false);

    Ok(any_ip_address_matches || (cmp_hostname && any_hostname_matches))
}

pub struct Host;

function_set! {
    Host,
    (
        get_host_names,
        (nasl_get_host_ip, "get_host_ip"),
        resolve_host_name,
        resolve_hostname_to_multiple_ips,
        (target_is_ipv6, "TARGET_IS_IPV6"),
        same_host,
        add_host_name,
        get_host_name,
        get_host_name_source
    )
}
