// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::net::{IpAddr, Ipv4Addr};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{self, Packet, tcp::MutableTcpPacket};

use crate::nasl::raw_ip_utils::raw_ip_utils::{get_source_ip, get_source_ipv4, ChecksumCalculator};
use crate::nasl::builtin::misc::random_impl;
use super::common::{DEFAULT_TTL, HEADER_LENGTH, IP_LENGTH, IP_PPRTO_VERSION_IPV4};
use super::AliveTestError;

pub const FILTER_PORT: u16 = 9910;
pub const TH_SYN: u16 = 0x02;
pub const TH_ACK: u16 = 0x10;
pub const TCP_LENGTH: usize = 20;

pub fn tcp_ping(dport: u16, tcp_flag: u16) -> Vec<u8> {
    
    let mut tcp_buf = vec![0u8; TCP_LENGTH];
    // knwon buffer size.
    let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp.set_flags(tcp_flag); //TH_SYN: 0x02, TH_ACK: 0x10
    tcp.set_sequence(random_impl().unwrap() as u32);
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(5);
    tcp.set_window(2048);
    tcp.set_urgent_ptr(0);
    tcp.set_source(FILTER_PORT);
    tcp.set_destination(dport);
    tcp_buf
}

fn forge_ipv4_packet_for_tcp(tcp_buf: &mut Vec<u8>, dst: Ipv4Addr) -> Ipv4Packet<'static> {
    // We do now the same as above for the IPv4 packet, appending the icmp packet as payload
    let mut ip_buf = vec![0; IP_LENGTH + TCP_LENGTH];

    let total_length = ip_buf.len();
    // Since we control the buffer size, we can safely unwrap here.
    let mut pkt = MutableIpv4Packet::new(&mut ip_buf).unwrap();

    pkt.set_header_length(HEADER_LENGTH);
    pkt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    pkt.set_ttl(0x40);
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

    Ipv4Packet::owned(ip_buf).unwrap()
}

pub fn forge_tcp_ping(dst: Ipv4Addr, dport: &u16, tcp_flag: u16) -> Ipv4Packet<'static> {
    let mut tcp_buf = tcp_ping(*dport, tcp_flag);
    forge_ipv4_packet_for_tcp(&mut tcp_buf, dst)
}
