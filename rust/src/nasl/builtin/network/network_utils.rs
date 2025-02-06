// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module provides utility functions for IP handling.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ptr,
    str::FromStr,
    time::Duration,
};

use super::socket::SocketError;

/// Convert a string in a IpAddr
pub fn ipstr2ipaddr(ip_addr: &str) -> Result<IpAddr, SocketError> {
    match IpAddr::from_str(ip_addr) {
        Ok(ip) => Ok(ip),
        Err(_) => Err(SocketError::InvalidIpAddress(ip_addr.into())),
    }
}

/// Convert timeout
pub fn convert_timeout(timeout: Option<i64>) -> Option<Duration> {
    timeout
        .filter(|timeout| *timeout >= 1)
        .map(|timeout| Duration::from_secs(timeout as u64))
}

/// Bind a local UDP socket to a V4 or V6 address depending on the given destination address
pub fn bind_local_socket(dst: &SocketAddr) -> Result<UdpSocket, SocketError> {
    let fe = |e| Err(SocketError::FailedToBindSocket(e, *dst));
    match dst {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").or_else(fe),
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").or_else(fe),
    }
}

/// Return the source IP address given the destination IP address
pub fn get_source_ip(dst: IpAddr, port: u16) -> Result<IpAddr, SocketError> {
    let socket = SocketAddr::new(dst, port);
    let sd = format!("{}:{}", dst, port);
    let local_socket = bind_local_socket(&socket)?;
    local_socket
        .connect(sd)
        .ok()
        .and_then(|_| local_socket.local_addr().ok())
        .and_then(|l_addr| IpAddr::from_str(&l_addr.ip().to_string()).ok())
        .ok_or(SocketError::NoRouteToDestination(dst))
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
pub fn get_netmask_by_local_ip(local_address: IpAddr) -> Result<Option<IpAddr>, SocketError> {
    let mut interfaces: *mut libc::ifaddrs = ptr::null_mut();

    let ret = unsafe { libc::getifaddrs(&mut interfaces) };

    if ret < 0 {
        return Err(SocketError::Diagnostic(
            "Error getting interfaces".to_string(),
        ));
    }

    let mut interface_iter = interfaces;

    while !interface_iter.is_null() {
        let interface = unsafe { &*interface_iter };

        if !interface.ifa_addr.is_null() {
            // Dereferencing raw pointers is unsafe
            unsafe {
                let addr = (*interface.ifa_addr).sa_family;
                let (ip, net) = match addr as i32 {
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
                };
                if ip == local_address {
                    libc::freeifaddrs(interfaces);
                    return Ok(net);
                }
            }
        }
        interface_iter = interface.ifa_next;
    }

    unsafe {
        libc::freeifaddrs(interfaces);
    }
    Err(SocketError::NoRouteToDestination(local_address))
}
