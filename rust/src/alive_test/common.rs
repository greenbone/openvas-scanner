// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use pnet::packet::{Packet, ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use socket2::{Domain, Protocol, Socket};
use std::net::{IpAddr, SocketAddr};

use super::AliveTestError;

const IPPROTO_RAW: i32 = 255;
pub const DEFAULT_TTL: u8 = 255;
pub const IP_PPRTO_VERSION_IPV4: u8 = 4;
pub const IP_LENGTH: usize = 20;
pub const HEADER_LENGTH: u8 = 5;
pub const FIX_IPV6_HEADER_LENGTH: usize = 40;
pub const IPPROTO_IPV6: u8 = 6;

pub fn new_raw_socket() -> Result<Socket, AliveTestError> {
    Socket::new_raw(
        Domain::IPV4,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    )
    .map_err(|e| AliveTestError::NoSocket(e.to_string()))
}

pub fn new_raw_socket_v6() -> Result<Socket, AliveTestError> {
    Socket::new_raw(
        Domain::IPV6,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    )
    .map_err(|e| AliveTestError::NoSocket(e.to_string()))
}

// Send ipv6 packet
pub fn alive_test_send_v6_packet(pkt: Ipv6Packet<'static>) -> Result<(), AliveTestError> {
    tracing::debug!("starting sending packet");
    let sock = new_raw_socket_v6()?;
    sock.set_header_included_v6(true)
        .map_err(|e| AliveTestError::NoSocket(e.to_string()))?;

    let sockaddr = SocketAddr::new(IpAddr::from(pkt.get_destination()), 0);
    match sock.send_to(pkt.packet(), &sockaddr.into()) {
        Ok(b) => {
            tracing::debug!("Sent {} bytes", b);
        }
        Err(e) => {
            return Err(AliveTestError::SendPacket(e.to_string()));
        }
    };
    Ok(())
}

// Send ipv4 packet
pub fn alive_test_send_v4_packet(pkt: Ipv4Packet<'static>) -> Result<(), AliveTestError> {
    tracing::debug!("starting sending packet");
    let sock = new_raw_socket()?;
    sock.set_header_included_v4(true)
        .map_err(|e| AliveTestError::NoSocket(e.to_string()))?;

    let sockaddr = SocketAddr::new(IpAddr::from(pkt.get_destination()), 0);
    match sock.send_to(pkt.packet(), &sockaddr.into()) {
        Ok(b) => {
            tracing::debug!("Sent {} bytes", b);
        }
        Err(e) => {
            return Err(AliveTestError::SendPacket(e.to_string()));
        }
    };
    Ok(())
}
