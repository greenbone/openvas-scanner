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

use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::*, udp::MutableUdpPacket};

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

pub fn get_mtu(target_ip: IpAddr) -> Result<usize, RawIpError> {
    let (_, mtu): (String, usize) =
        mtu::interface_and_mtu(target_ip).map_err(|_| RawIpError::FailedToGetDeviceMTU)?;
    Ok(mtu)
}

pub fn bind_local_socket(dst: &SocketAddr) -> Result<UdpSocket, RawIpError> {
    match dst {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
        SocketAddr::V6(_) => UdpSocket::bind("[0:0:0:0:0:0:0:0]:0"),
    }
    .map_err(RawIpError::FailedToBind)
}

/// Return the source IP address given the destination IP address
pub fn get_source_ip(dst: IpAddr) -> Result<IpAddr, FnError> {
    let fake_port = 50000u16;
    let socket = SocketAddr::new(dst, fake_port);
    let sd = format!("{}:{}", dst, fake_port);
    let local_socket = bind_local_socket(&socket)?;
    local_socket
        .connect(sd)
        .ok()
        .and_then(|_| local_socket.local_addr().ok())
        .and_then(|l_addr| IpAddr::from_str(&l_addr.ip().to_string()).ok())
        .ok_or(RawIpError::NoRouteToDestination.into())
}

pub fn get_source_ipv6(dst: Ipv6Addr) -> Result<Ipv6Addr, FnError> {
    match get_source_ip(IpAddr::from(dst)) {
        Ok(IpAddr::V6(a)) => Ok(a),
        _ => return Err(RawIpError::NoRouteToDestination.into()),
    }
}

pub fn get_source_ipv4(dst: Ipv4Addr) -> Result<Ipv4Addr, FnError> {
    match get_source_ip(IpAddr::from(dst)) {
        Ok(IpAddr::V4(a)) => Ok(a),
        _ => return Err(RawIpError::NoRouteToDestination.into()),
    }
}

pub trait ChecksumCalculator<'a, V: 'a> {
    fn calculate_checksum(&self, chksum: Option<u16>, pkt: &'a V) -> u16;
}

impl<'a> ChecksumCalculator<'a, Ipv4Packet<'a>> for MutableUdpPacket<'a> {
    fn calculate_checksum(&self, chksum: Option<u16>, pkt: &'a Ipv4Packet) -> u16 {
        let chksum = chksum.unwrap_or(0);
        if chksum != 0 {
            return chksum.to_be();
        }
        pnet::packet::udp::ipv4_checksum(
            &self.to_immutable(),
            &pkt.get_source(),
            &pkt.get_destination(),
        )
    }
}

impl<'a> ChecksumCalculator<'a, Ipv4Packet<'a>> for MutableTcpPacket<'a> {
    fn calculate_checksum(&self, chksum: Option<u16>, pkt: &'a Ipv4Packet) -> u16 {
        let chksum = chksum.unwrap_or(0);
        if chksum != 0 {
            return chksum.to_be();
        }
        pnet::packet::tcp::ipv4_checksum(
            &self.to_immutable(),
            &pkt.get_source(),
            &pkt.get_destination(),
        )
    }
}

impl<'a> ChecksumCalculator<'a, Ipv6Packet<'a>> for MutableUdpPacket<'a> {
    fn calculate_checksum(&self, chksum: Option<u16>, pkt: &'a Ipv6Packet) -> u16 {
        let chksum = chksum.unwrap_or(0);
        if chksum != 0 {
            return chksum.to_be();
        }
        pnet::packet::udp::ipv6_checksum(
            &self.to_immutable(),
            &pkt.get_source(),
            &pkt.get_destination(),
        )
    }
}

impl<'a> ChecksumCalculator<'a, Ipv6Packet<'a>> for MutableTcpPacket<'a> {
    fn calculate_checksum(&self, chksum: Option<u16>, pkt: &'a Ipv6Packet) -> u16 {
        let chksum = chksum.unwrap_or(0);
        if chksum != 0 {
            return chksum.to_be();
        }
        pnet::packet::tcp::ipv6_checksum(
            &self.to_immutable(),
            &pkt.get_source(),
            &pkt.get_destination(),
        )
    }
}
