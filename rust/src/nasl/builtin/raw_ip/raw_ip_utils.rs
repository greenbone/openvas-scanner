// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str::FromStr,
};

use crate::nasl::prelude::*;
use pcap::{Address, Device};

use super::RawIpError;

/// Convert a string in a IpAddr
pub fn ipstr2ipaddr(ip_addr: &str) -> Result<IpAddr, FnError> {
    match IpAddr::from_str(ip_addr) {
        Ok(ip) => Ok(ip),
        Err(_) => Err(FnError::from(ArgumentError::WrongArgument(
            "Invalid IP address".to_string(),
        ))
        .with(ReturnValue(NaslValue::Null))),
    }
}

/// Tests whether a packet sent to IP is LIKELY to route through the
/// kernel localhost interface
pub fn islocalhost(addr: IpAddr) -> bool {
    // If it is not 0.0.0.0 or doesn't start with 127.0.0.1 then it
    // probably isn't localhost
    if !addr.is_loopback() || !addr.is_unspecified() {
        return false;
    }
    // It is not associated to a local interface.
    if let Err(_e) = get_interface_by_local_ip(addr) {
        return false;
    }

    true
}

/// Get the interface from the local ip
pub fn get_interface_by_local_ip(local_address: IpAddr) -> Result<Device, FnError> {
    // This fake IP is used for matching (and return false)
    // during the search of the interface in case an interface
    // doesn't have an associated address.

    let fake_ip = match local_address {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let fake_addr = Address {
        addr: fake_ip,
        broadcast_addr: None,
        netmask: None,
        dst_addr: None,
    };

    let ip_match = |ip: &Address| ip.addr.eq(&local_address);

    let devices = Device::list().map_err(|_| RawIpError::FailedToGetDeviceList)?;
    devices
        .into_iter()
        .find(|x| {
            local_address
                == (x.addresses.clone().into_iter().find(ip_match))
                    .unwrap_or_else(|| fake_addr.to_owned())
                    .addr
        })
        .ok_or(RawIpError::InvalidIpAddress.into())
}

pub fn bind_local_socket(dst: &SocketAddr) -> Result<UdpSocket, RawIpError> {
    match dst {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
        SocketAddr::V6(_) => UdpSocket::bind(" 0:0:0:0:0:0:0:0:0"),
    }
    .map_err(RawIpError::FailedToBind)
}

/// Return the source IP address given the destination IP address
pub fn get_source_ip(dst: IpAddr, port: u16) -> Result<IpAddr, FnError> {
    let socket = SocketAddr::new(dst, port);
    let sd = format!("{}:{}", dst, port);
    let local_socket = bind_local_socket(&socket)?;
    local_socket
        .connect(sd)
        .ok()
        .and_then(|_| local_socket.local_addr().ok())
        .and_then(|l_addr| IpAddr::from_str(&l_addr.ip().to_string()).ok())
        .ok_or(RawIpError::NoRouteToDestination.into())
}
