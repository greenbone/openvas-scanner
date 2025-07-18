// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::net::{Ipv4Addr, Ipv6Addr};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::{Packet, tcp::MutableTcpPacket};

use super::AliveTestError;
use super::common::{
    DEFAULT_TTL, FIX_IPV6_HEADER_LENGTH, HEADER_LENGTH, IP_LENGTH, IP_PPRTO_VERSION_IPV4,
    IPPROTO_IPV6,
};
use crate::nasl::builtin::misc::random_impl;
use crate::nasl::raw_ip_utils::raw_ip_utils::{
    ChecksumCalculator, get_source_ipv4, get_source_ipv6,
};

pub const FILTER_PORT: u16 = 9910;
pub const TCP_LENGTH: usize = 20;

#[derive(PartialEq, Eq)]
pub enum TcpFlags {
    Empty = 0x00,
    ThSyn = 0x02,
    ThAck = 0x10,
}

impl From<u16> for TcpFlags {
    fn from(value: u16) -> Self {
        match value {
            0x02 => Self::ThSyn,
            0x10 => Self::ThAck,
            _ => Self::Empty,
        }
    }
}

pub fn tcp_ping(dport: u16, tcp_flag: u16) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; TCP_LENGTH];
    // knwon buffer size.
    let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp.set_flags(tcp_flag); //TH_SYN: 0x02, TH_ACK: 0x10
    tcp.set_sequence(random_impl().unwrap() as u32);
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(5);
    tcp.set_window(8);
    tcp.set_urgent_ptr(0);
    tcp.set_source(FILTER_PORT);
    tcp.set_destination(dport);
    tcp_buf
}

fn forge_ipv4_packet_for_tcp(
    tcp_buf: &mut Vec<u8>,
    dst: Ipv4Addr,
) -> Result<Ipv4Packet<'static>, AliveTestError> {
    // We do now the same as above for the IPv4 packet, appending the icmp packet as payload
    let mut ip_buf = vec![0; IP_LENGTH + TCP_LENGTH];

    let total_length = ip_buf.len();
    // Since we control the buffer size, we can safely unwrap here.
    let mut pkt = MutableIpv4Packet::new(&mut ip_buf).unwrap();

    pkt.set_header_length(HEADER_LENGTH);
    pkt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    pkt.set_ttl(0x40);
    pkt.set_source(get_source_ipv4(dst).map_err(|_| AliveTestError::InvalidDestinationAddr)?);
    pkt.set_destination(dst);
    pkt.set_fragment_offset(0);
    pkt.set_identification(random_impl().unwrap() as u16);
    pkt.set_version(IP_PPRTO_VERSION_IPV4);
    pkt.set_total_length(total_length as u16);
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    let mut tcp = MutableTcpPacket::new(tcp_buf).unwrap();
    let chksum = tcp.calculate_checksum(None, &pkt.to_immutable());
    tcp.set_checksum(chksum);
    pkt.set_payload(tcp.packet());

    Ok(Ipv4Packet::owned(ip_buf).unwrap())
}

pub fn forge_tcp_ping(
    dst: Ipv4Addr,
    dport: &u16,
    tcp_flag: u16,
) -> Result<Ipv4Packet<'static>, AliveTestError> {
    let mut tcp_buf = tcp_ping(*dport, tcp_flag);
    forge_ipv4_packet_for_tcp(&mut tcp_buf, dst)
}

fn forge_ipv6_packet_for_tcp(
    tcp_buf: &mut Vec<u8>,
    dst: Ipv6Addr,
) -> Result<Ipv6Packet<'static>, AliveTestError> {
    let tcp_buf_len = tcp_buf.len();
    // We do now the same as above for the IPv4 packet, appending the icmp packet as payload
    let mut ip_buf = vec![0; FIX_IPV6_HEADER_LENGTH + tcp_buf_len];
    // Since we control the buffer size, we can safely unwrap here.
    let mut pkt = MutableIpv6Packet::new(&mut ip_buf).unwrap();

    pkt.set_next_header(IpNextHeaderProtocols::Tcp);
    pkt.set_hop_limit(DEFAULT_TTL);
    pkt.set_source(get_source_ipv6(dst).map_err(|_| AliveTestError::InvalidDestinationAddr)?);
    pkt.set_destination(dst);
    pkt.set_version(IPPROTO_IPV6);

    let mut tcp = MutableTcpPacket::new(tcp_buf).unwrap();
    let chksum = tcp.calculate_checksum(None, &pkt.to_immutable());
    tcp.set_checksum(chksum);
    pkt.set_payload_length(tcp_buf_len as u16);
    pkt.set_payload(&tcp_buf);

    //we know the buffer size. So, it never fails
    Ok(Ipv6Packet::owned(ip_buf).unwrap())
}

pub fn forge_tcp_ping_ipv6(
    dst: Ipv6Addr,
    dport: &u16,
    tcp_flag: u16,
) -> Result<Ipv6Packet<'static>, AliveTestError> {
    let mut tcp_buf = tcp_ping(*dport, tcp_flag);
    forge_ipv6_packet_for_tcp(&mut tcp_buf, dst)
}
