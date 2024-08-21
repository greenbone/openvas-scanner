// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module provides utility functions for IP handling.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ptr,
    str::FromStr,
};

use nasl_syntax::NaslValue;

use crate::FunctionErrorKind;

/// Convert a string in a IpAddr
pub fn ipstr2ipaddr(ip_addr: &str) -> Result<IpAddr, FunctionErrorKind> {
    match IpAddr::from_str(ip_addr) {
        Ok(ip) => Ok(ip),
        Err(_) => Err(FunctionErrorKind::Diagnostic(
            format!("Invalid IP address ({})", ip_addr),
            Some(NaslValue::Null),
        )),
    }
}

/// Bind a local UDP socket to a V4 or V6 address depending on the given destination address
pub fn bind_local_socket(dst: &SocketAddr) -> Result<UdpSocket, FunctionErrorKind> {
    let fe = Err(FunctionErrorKind::Diagnostic(
        "Error binding".to_string(),
        None,
    ));
    match dst {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").or(fe),
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").or(fe),
    }
}

/// Return the source IP address given the destination IP address
pub fn get_source_ip(dst: IpAddr, port: u16) -> Result<IpAddr, FunctionErrorKind> {
    let socket = SocketAddr::new(dst, port);
    let sd = format!("{}:{}", dst, port);
    let local_socket = bind_local_socket(&socket)?;
    match local_socket.connect(sd) {
        Ok(_) => match local_socket.local_addr() {
            Ok(l_addr) => match IpAddr::from_str(&l_addr.ip().to_string()) {
                Ok(x) => Ok(x),
                Err(_) => Err(FunctionErrorKind::Diagnostic(
                    "No route to destination".to_string(),
                    None,
                )),
            },
            Err(_) => Err(FunctionErrorKind::Diagnostic(
                "No route to destination".to_string(),
                None,
            )),
        },
        Err(_) => Err(FunctionErrorKind::Diagnostic(
            "No route to destination".to_string(),
            None,
        )),
    }
}

/// Tests whether a packet sent to IP is LIKELY to route through the
/// kernel localhost interface
pub fn islocalhost(addr: IpAddr) -> bool {
    // If it is not 0.0.0.0 or doesn't start with 127.0.0.1 then it
    // probably isn't localhost
    if addr.is_loopback() || addr.is_unspecified() {
        return true;
    }
    // It is associated to a local interface.
    get_netmask_by_local_ip(addr).is_ok()
}

/// Get the interface from the local ip
pub fn get_netmask_by_local_ip(local_address: IpAddr) -> Result<Option<IpAddr>, FunctionErrorKind> {
    // This fake IP is used for matching (and return false)
    // during the search of the interface in case an interface
    // doesn't have an associated address.

    let mut interfaces: *mut libc::ifaddrs = ptr::null_mut();

    unsafe {
        libc::getifaddrs(&mut interfaces);
    };

    let mut interface_iter = interfaces;

    while !interface_iter.is_null() {
        let interface = unsafe { &*interface_iter };

        if !interface.ifa_addr.is_null() {
            let addr = unsafe { (*interface.ifa_addr).sa_family };
            let (ip, net) = unsafe {
                match addr as i32 {
                    libc::AF_INET => {
                        let addr = interface.ifa_addr as *const libc::sockaddr_in;
                        let addr = &*addr;
                        let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
                        if !interface.ifa_netmask.is_null() {
                            let addr = interface.ifa_netmask as *const libc::sockaddr_in;
                            let addr = &*addr;
                            let net =
                                IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
                            (ip, Some(net))
                        } else {
                            (ip, None)
                        }
                    }
                    libc::AF_INET6 => {
                        let addr = interface.ifa_addr as *const libc::sockaddr_in6;
                        let addr = &*addr;
                        let ip = IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr));
                        if !interface.ifa_netmask.is_null() {
                            let addr = interface.ifa_netmask as *const libc::sockaddr_in6;
                            let addr = &*addr;
                            let net = IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr));
                            (ip, Some(net))
                        } else {
                            (ip, None)
                        }
                    }
                    _ => {
                        interface_iter = interface.ifa_next;
                        continue;
                    }
                }
            };

            if ip == local_address {
                unsafe {
                    libc::freeifaddrs(interfaces);
                }
                return Ok(net);
            }
        }
        interface_iter = interface.ifa_next;
    }

    unsafe {
        libc::freeifaddrs(interfaces);
    }
    Err(FunctionErrorKind::Diagnostic(
        "No route to destination".to_string(),
        None,
    ))
}

pub fn expand_ipv6(ip: &str) -> String {
    if let Some((left, right)) = ip.split_once("::") {
        let left_parts = left.split(':').collect::<Vec<&str>>();
        let right_parts = right.split(':').collect::<Vec<&str>>();
        let mut expanded = String::new();
        let missing = 8 - left_parts.len() - right_parts.len();
        for part in left_parts {
            expanded.push_str(part);
            expanded.push(':');
        }
        for _ in 0..missing {
            expanded.push_str("0000:");
        }
        for part in right_parts {
            expanded.push_str(part);
            expanded.push(':');
        }
        expanded.pop();
        expanded
    } else {
        ip.to_string()
    }
}

pub fn ipv6_parts(ip: &str) -> Vec<String> {
    expand_ipv6(ip).split(':').map(|s| s.to_string()).collect()
}
