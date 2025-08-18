// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use crate::nasl::raw_ip_utils::raw_ip_utils::get_source_ipv6;

use super::AliveTestError;
use super::common::FIX_IPV6_HEADER_LENGTH;
use super::common::IPPROTO_IPV6;
use super::common::{DEFAULT_TTL, HEADER_LENGTH, IP_LENGTH, IP_PPRTO_VERSION_IPV4};
use pnet::packet::icmpv6::Icmpv6Code;
use pnet::packet::icmpv6::Icmpv6Type;
use pnet::packet::icmpv6::ndp::MutableNeighborSolicitPacket;
use pnet::packet::{
    self, Packet,
    icmp::*,
    icmpv6::{
        Icmpv6Types, MutableIcmpv6Packet, echo_reply::Icmpv6Codes,
        echo_request::MutableEchoRequestPacket,
    },
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet, checksum},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
};

const ICMP_LENGTH: usize = 8;
// This is the only possible code for an echo request
const ICMP_ECHO_REQ_CODE: u8 = 0;

// ICMPv4

fn forge_icmp_packet() -> Vec<u8> {
    // Create an icmp packet from a buffer and modify it.
    let mut buf = vec![0; ICMP_LENGTH];
    // Since we control the buffer size, we can safely unwrap here.
    let mut icmp_pkt = MutableIcmpPacket::new(&mut buf).unwrap();
    icmp_pkt.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_pkt.set_icmp_code(IcmpCode::new(ICMP_ECHO_REQ_CODE));
    icmp_pkt.set_checksum(pnet::packet::icmp::checksum(&icmp_pkt.to_immutable()));
    buf
}

fn forge_ipv4_packet_for_icmp(icmp_buf: &mut Vec<u8>, dst: Ipv4Addr) -> Ipv4Packet<'static> {
    // We do now the same as above for the IPv4 packet, appending the icmp packet as payload
    let mut ip_buf = vec![0; IP_LENGTH];
    ip_buf.append(icmp_buf);
    let total_length = ip_buf.len();
    // Since we control the buffer size, we can safely unwrap here.
    let mut pkt = MutableIpv4Packet::new(&mut ip_buf).unwrap();

    pkt.set_header_length(HEADER_LENGTH);
    pkt.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    pkt.set_ttl(DEFAULT_TTL);
    pkt.set_destination(dst);

    pkt.set_version(IP_PPRTO_VERSION_IPV4);
    pkt.set_total_length(total_length as u16);
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ipv4Packet::owned(ip_buf).unwrap()
}

pub fn forge_icmp_v4(dst: Ipv4Addr) -> Ipv4Packet<'static> {
    let mut icmp_buf = forge_icmp_packet();
    forge_ipv4_packet_for_icmp(&mut icmp_buf, dst)
}

// ICMPv6

fn forge_icmp_v6_packet() -> Vec<u8> {
    // Create an icmp packet from a buffer and modify it.
    let mut icmp_v6_buf = vec![0; MutableEchoRequestPacket::minimum_packet_size()];
    // Since we control the buffer size, we can safely unwrap here.
    let mut icmp_pkt = MutableIcmpv6Packet::new(&mut icmp_v6_buf).unwrap();
    icmp_pkt.set_icmpv6_code(Icmpv6Codes::NoCode);
    icmp_pkt.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmp_v6_buf
}

fn forge_ipv6_packet_for_icmp(
    icmp_buf: &mut [u8],
    dst: Ipv6Addr,
) -> Result<Ipv6Packet<'static>, AliveTestError> {
    let icmp_buf_len = icmp_buf.len();
    // We do now the same as above for the IPv4 packet, appending the icmp packet as payload
    let mut ip_buf = vec![0; FIX_IPV6_HEADER_LENGTH + icmp_buf_len];
    // Since we control the buffer size, we can safely unwrap here.
    let mut pkt = MutableIpv6Packet::new(&mut ip_buf).unwrap();

    pkt.set_next_header(IpNextHeaderProtocols::Icmpv6);
    pkt.set_hop_limit(DEFAULT_TTL);
    pkt.set_source(
        get_source_ipv6(dst).map_err(|e| AliveTestError::InvalidDestinationAddr(e.to_string()))?,
    );
    pkt.set_destination(dst);
    pkt.set_version(IPPROTO_IPV6);
    let icmp_buf_len = icmp_buf.len() as i64;
    let mut icmp_pkt = packet::icmpv6::MutableIcmpv6Packet::new(icmp_buf).ok_or(
        AliveTestError::CreateIcmpPacketFromWrongBufferSize(icmp_buf_len),
    )?;

    let chksum = pnet::packet::icmpv6::checksum(
        &icmp_pkt.to_immutable(),
        &pkt.get_source(),
        &pkt.get_destination(),
    );
    icmp_pkt.set_checksum(chksum);

    pkt.set_payload_length(icmp_buf_len as u16);
    pkt.set_payload(icmp_buf);

    //we know the buffer size. So, it never fails
    Ok(Ipv6Packet::owned(ip_buf).unwrap())
}

pub fn forge_neighbor_solicit(dst_ip: Ipv6Addr) -> Result<Ipv6Packet<'static>, AliveTestError> {
    let mut icmp_buf = vec![0; MutableNeighborSolicitPacket::minimum_packet_size()];
    let mut icmp_pkt = MutableNeighborSolicitPacket::new(&mut icmp_buf).unwrap();
    let icmp_type = Icmpv6Type::new(Icmpv6Types::NeighborSolicit.0);

    icmp_pkt.set_icmpv6_type(icmp_type);
    icmp_pkt.set_icmpv6_code(Icmpv6Code::new(0u8));
    icmp_pkt.set_target_addr(dst_ip);

    forge_ipv6_packet_for_icmp(&mut icmp_pkt.packet().to_vec(), dst_ip)
}

pub fn forge_icmp_v6(dst: Ipv6Addr) -> Result<Ipv6Packet<'static>, AliveTestError> {
    let mut icmp_buf = forge_icmp_v6_packet();
    forge_ipv6_packet_for_icmp(&mut icmp_buf, dst)
}
