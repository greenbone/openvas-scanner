// Copyright (C) 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL packet forgery functions

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use super::{
    PacketForgeryError, RawIpError,
    raw_ip_utils::{get_interface_by_local_ip, get_source_ip, islocalhost, ChecksumCalculator},
};

use crate::nasl::prelude::*;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::NaslVars;
use crate::nasl::{builtin::misc::random_impl, utils::function::utils::DEFAULT_TIMEOUT};

use pcap::Capture;
use pnet::packet::{
    self, Packet, PrimitiveValues,
    ethernet::EthernetPacket,
    icmp::*,
    icmpv6::{
        Icmpv6Code, Icmpv6Packet, Icmpv6Types,
        echo_request::MutableEchoRequestPacket,
        ndp::{
            MutableNeighborAdvertPacket, MutableNeighborSolicitPacket, MutableRouterAdvertPacket,
            MutableRouterSolicitPacket,
        },
    },
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Packet, MutableIpv4Packet, checksum},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    tcp::{TcpOption, TcpOptionNumbers, TcpPacket, *},
    udp::{MutableUdpPacket, UdpPacket},
};

use pnet_macros_support::types::u9be;
use socket2::{Domain, Protocol, Socket};
use tracing::debug;

fn error(s: String) -> FnError {
    PacketForgeryError::Custom(s).into()
}

macro_rules! custom_error {
    ($a:expr, $b:expr) => {
        Err(RawIpError::PacketForgery(PacketForgeryError::Custom(format!($a, $b))).into())
    };
}

/// Define IPPROTO_RAW
const IPPROTO_RAW: i32 = 255;
/// Define IPPROTO_IP for dummy tcp . From rfc3542:
// Berkeley-derived IPv4 implementations also define IPPROTO_IP to be 0.
// This should not be a problem since IPPROTO_IP is used only with IPv4
// sockets and IPPROTO_HOPOPTS only with IPv6 sockets.
const IPPROTO_IP: u8 = 0;
const IPPROTO_IPV6: u8 = 6;
/// Reserved fragment flag
const IP_RF: i64 = 0x8000;
/// Dont fragment flag
const IP_DF: i64 = 0x4000;
/// More fragments flag
const IP_MF: i64 = 0x2000;
/// Mask for fragmenting bits
const IP_OFFMASK: i64 = 0x1fff;
/// Minimum header length for IPv4 Packet Header
const MIN_IPV4_HEADER_LENGTH: usize = 20;
/// Fixed header length for IPv6 Packet Header
const FIX_IPV6_HEADER_LENGTH: usize = 40;
/// Total length for TCP Packet
const TOTAL_TCP_HEADER_LENGTH: u16 = 40;
/// Minimum header length for TCP Packet Header
const MIN_TCP_HEADER_LENGTH: usize = 20;
/// Minimum header length for UDP Packet Header
const MIN_UDP_HEADER_LENGTH: usize = 8;
/// Minimum header length for ICMP Packet Header
const MIN_ICMP_HEADER_LENGTH: usize = 8;
/// Default header length for IPv4 Packet Header in chunk of 32bits.
/// Used in the header length field. This the minimum 20bytes.
const DEFAULT_IPV4_HEADER_LENGTH_32BIT_INCREMENTS: u8 = 5;
/// Used in the header length field. This the minimum 20bytes.
const DEFAULT_TCP_DATA_OFFSET_32BIT_INCREMENTS: u8 = 5;
/// Default ttl value is inherit from NASL C
const DEFAULT_TTL: u8 = 0x40;
const TH_SYN: u16 = 0x02;

#[derive(Default)]
struct PacketPayload {
    data: Vec<u8>,
}

impl From<Vec<u8>> for PacketPayload {
    fn from(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl From<PacketPayload> for Vec<u8> {
    fn from(data: PacketPayload) -> Self {
        data.data
    }
}

impl<'a> FromNaslValue<'a> for PacketPayload {
    fn from_nasl_value(data: &'a NaslValue) -> Result<Self, FnError> {
        match data {
            NaslValue::Data(d) => Ok(d.clone().into()),
            NaslValue::String(d) => Ok(d.as_bytes().to_vec().into()),
            NaslValue::Number(d) => Ok(d.to_be_bytes().to_vec().into()),
            _ => Ok(Vec::<u8>::new().into()),
        }
    }
}

impl<'a> FromNaslValue<'a> for Ipv4Packet<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let buf: &[u8] = <&[u8]>::from_nasl_value(val)?;
        let ip = Ipv4Packet::new(buf).ok_or(BuiltinError::RawIp(RawIpError::PacketForgery(
            PacketForgeryError::CreateIpv4Packet,
        )))?;
        Ok(ip)
    }
}

impl<'a> FromNaslValue<'a> for Ipv6Packet<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let buf: &[u8] = <&[u8]>::from_nasl_value(val)?;
        let ip = Ipv6Packet::new(buf).ok_or(BuiltinError::RawIp(RawIpError::PacketForgery(
            PacketForgeryError::CreateIpv6Packet,
        )))?;
        Ok(ip)
    }
}

fn get_payload_from_packet(val: &NaslValue) -> Result<Vec<u8>, FnError> {
    // It expects an Ipv4 or Ipv6 packet. Before to get a packet to the right
    // version, we need to know the version. So, we extract this from the header.
    let first_4bits = (<&[u8]>::from_nasl_value(val)?[0] & 0b11110000) >> 4;
    match first_4bits {
        4 => {
            let ip: Ipv4Packet = Ipv4Packet::from_nasl_value(val)?;
            Ok(ip.payload().to_vec())
        }
        6 => {
            let ip: Ipv6Packet = Ipv6Packet::from_nasl_value(val)?;
            Ok(ip.payload().to_vec())
        }
        _ => Err(BuiltinError::RawIp(RawIpError::PacketForgery(
            PacketForgeryError::CreateTcpPacket,
        ))
        .into()),
    }
}

impl<'a> FromNaslValue<'a> for UdpPacket<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let payload = get_payload_from_packet(val)?;
        let udp = UdpPacket::owned(payload).ok_or(BuiltinError::RawIp(
            RawIpError::PacketForgery(PacketForgeryError::CreateUdpPacket),
        ))?;
        Ok(udp)
    }
}

impl<'a> FromNaslValue<'a> for TcpPacket<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let payload = get_payload_from_packet(val)?;
        let tcp = TcpPacket::owned(payload).ok_or(BuiltinError::RawIp(
            RawIpError::PacketForgery(PacketForgeryError::CreateTcpPacket),
        ))?;
        Ok(tcp)
    }
}

impl<'a> FromNaslValue<'a> for IcmpPacket<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let payload = get_payload_from_packet(val)?;
        let icmp = IcmpPacket::owned(payload).ok_or(BuiltinError::RawIp(
            RawIpError::PacketForgery(PacketForgeryError::CreateIcmpPacket),
        ))?;
        Ok(icmp)
    }
}

impl<'a> FromNaslValue<'a> for Icmpv6Packet<'a> {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let payload = get_payload_from_packet(val)?;
        let icmp = Icmpv6Packet::owned(payload).ok_or(BuiltinError::RawIp(
            RawIpError::PacketForgery(PacketForgeryError::CreateIcmpPacket),
        ))?;
        Ok(icmp)
    }
}

impl<'a> FromNaslValue<'a> for Ipv4Addr {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let addr = String::from_nasl_value(val)?;
        match addr.parse::<Ipv4Addr>() {
            Ok(ip_addr) => Ok(ip_addr),
            Err(e) => Err(ArgumentError::WrongArgument(
                format!("Expected a valid IPv4 address. {}.", e).to_string(),
            )
            .into()),
        }
    }
}

impl<'a> FromNaslValue<'a> for Ipv6Addr {
    fn from_nasl_value(val: &'a NaslValue) -> Result<Self, FnError> {
        let addr = String::from_nasl_value(val)?;
        match addr.parse::<Ipv6Addr>() {
            Ok(ip_addr) => Ok(ip_addr),
            Err(e) => Err(ArgumentError::WrongArgument(
                format!("Expected a valid IPv6 address. {}.", e).to_string(),
            )
            .into()),
        }
    }
}

/// print the raw packet
pub fn display_packet(vector: &[u8]) {
    let mut s: String = "\n".to_string();
    let mut count = 0;

    for e in vector {
        s.push_str(&format!("{:02x}", &e));
        count += 1;
        if count % 2 == 0 {
            s.push(' ');
        }
        if count % 16 == 0 {
            s.push('\n');
        }
    }
    println!("packet = {}", &s);
}


/// Copy from a slice in safe way, performing the necessary test to avoid panicking
pub fn safe_copy_from_slice(
    d_buf: &mut [u8],
    d_init: usize,
    d_fin: usize,
    o_buf: &[u8],
    o_init: usize,
    o_fin: usize,
) -> Result<(), FnError> {
    let o_range = o_fin - o_init;
    let d_range = d_fin - d_init;
    if d_buf.len() < d_range
        || o_buf.len() < o_range
        || o_range != d_range
        || d_buf.len() < d_fin
        || o_buf.len() < o_fin
    {
        return Err(error(
            "Error copying from slice. Index out of range".to_string(),
        ));
    }
    d_buf[d_init..d_fin].copy_from_slice(&o_buf[o_init..o_fin]);
    Ok(())
}

/// Forge an IP datagram inside the block of data. It takes following arguments:
///
/// - data: is the payload.
/// - ip_hl: is the IP header length in 32 bits words. 5 by default.
/// - ip_id: is the datagram ID; by default, it is random.
/// - ip_len: is the length of the datagram. By default, it is 20 plus the length of the data field.
/// - ip_off: is the fragment offset in 64 bits words. By default, 0.
/// - ip_p: is the IP protocol. 0 by default.
/// - ip_src: is the source address in ASCII. NASL will convert it into an integer in network order.
/// - ip_dst: is the destination address in ASCII. NASL will convert it into an integer in network order. By default it takes the target IP address via call to **[plug_get_host_ip(3)](plug_get_host_ip.md)**. This option looks dangerous, but since anybody can edit an IP packet with the string functions, we make it possible to set directly during the forge.
/// - ip_sum: is the packet header checksum. It will be computed by default.
/// - ip_tos: is the “type of service” field. 0 by default
/// - ip_ttl: is the “Time To Live”. 64 by default.
/// - ip_v is: the IP version. 4 by default.
///
/// Returns the IP datagram or NULL on error.
#[nasl_function(named(
    data, ip_hl, ip_v, ip_tos, ip_ttl, ip_id, ip_len, ip_off, ip_p, ip_src, ip_dst, ip_sum
))]
fn forge_ip_packet(
    configs: &ScanCtx,
    data: Option<PacketPayload>,
    ip_hl: Option<u8>,
    ip_v: Option<u8>,
    ip_tos: Option<u8>,
    ip_ttl: Option<u8>,
    ip_id: Option<u16>,
    ip_len: Option<u16>,
    ip_off: Option<u16>,
    ip_p: Option<u8>,
    ip_dst: Option<Ipv4Addr>,
    ip_src: Option<Ipv4Addr>,
    ip_sum: Option<u16>,
) -> Result<NaslValue, FnError> {
    let dst_addr = configs.target().ip_addr();
    if !dst_addr.is_ipv4() {
        return Err(ArgumentError::WrongArgument(
            "forge_ip_packet: No valid dst_addr could be determined via call to get_host_ip()"
                .to_string(),
        )
        .into());
    }

    let data: Vec<u8> = data.unwrap_or_default().into();
    let total_length = ip_len.unwrap_or(MIN_IPV4_HEADER_LENGTH as u16 + data.len() as u16);
    let mut buf = vec![0; total_length as usize];
    let mut pkt = MutableIpv4Packet::new(&mut buf).ok_or(PacketForgeryError::CreateIpv4Packet)?;

    pkt.set_total_length(total_length);
    if !data.is_empty() {
        pkt.set_payload(&data);
    }
    pkt.set_header_length(ip_hl.unwrap_or(DEFAULT_IPV4_HEADER_LENGTH_32BIT_INCREMENTS));
    pkt.set_version(ip_v.unwrap_or(IpNextHeaderProtocols::Ipv4.0));
    pkt.set_dscp(ip_tos.unwrap_or_default());
    pkt.set_ttl(ip_ttl.unwrap_or_default());
    pkt.set_identification(ip_id.unwrap_or(random_impl()? as u16).to_be());
    pkt.set_fragment_offset(ip_off.unwrap_or_default());
    pkt.set_next_level_protocol(IpNextHeaderProtocol::new(ip_p.unwrap_or_default()));

    if let Some(src) = ip_src {
        pkt.set_source(src);
    }
    let dst_addr = dst_addr.to_string().parse::<Ipv4Addr>().unwrap();
    if let Some(dst) = ip_dst {
        pkt.set_destination(dst);
    } else {
        pkt.set_destination(dst_addr);
    }
    let ip_sum = match ip_sum {
        Some(x) => x.to_be(),
        None => checksum(&pkt.to_immutable()),
    };
    pkt.set_checksum(ip_sum);
    Ok(NaslValue::Data(buf))
}

pub enum IpElement {
    HeaderLength,
    Id,
    IpLen,
    OffSet,
    IpProtocol,
    SourceAddress,
    DestinationAddress,
    Checksum,
    IpTOS,
    Ttl,
    Version,
}

impl FromStr for IpElement {
    type Err = ArgumentError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ip_hl" => Ok(IpElement::HeaderLength),
            "ip_id" => Ok(IpElement::Id),
            "ip_len" => Ok(IpElement::IpLen),
            "ip_off" => Ok(IpElement::OffSet),
            "ip_p" => Ok(IpElement::IpProtocol),
            "ip_sum" => Ok(IpElement::Checksum),
            "ip_tos" => Ok(IpElement::IpTOS),
            "ip_ttl" => Ok(IpElement::Ttl),
            "ip_v" => Ok(IpElement::Version),
            "ip_src" => Ok(IpElement::SourceAddress),
            "ip_dst" => Ok(IpElement::DestinationAddress),
            s => Err(ArgumentError::WrongArgument(format!(
                "Invalid element for IP packet: {}",
                s
            ))),
        }
    }
}

trait PacketElement {
    type Packet<'a>: pnet::packet::Packet;
    fn get_element(&self, packet: &Self::Packet<'_>) -> NaslValue;
}

impl PacketElement for IpElement {
    type Packet<'a> = Ipv4Packet<'a>;
    fn get_element(&self, pkt: &Self::Packet<'_>) -> NaslValue {
        match self {
            IpElement::Version => NaslValue::Number(pkt.get_version() as i64),
            IpElement::Id => NaslValue::Number(pkt.get_identification() as i64),
            IpElement::HeaderLength => NaslValue::Number(pkt.get_header_length() as i64),
            IpElement::IpTOS => NaslValue::Number(pkt.get_dscp() as i64),
            IpElement::IpLen => NaslValue::Number(pkt.get_total_length() as i64),
            IpElement::OffSet => NaslValue::Number(pkt.get_fragment_offset() as i64),
            IpElement::Ttl => NaslValue::Number(pkt.get_ttl() as i64),
            IpElement::IpProtocol => NaslValue::Number(pkt.get_next_level_protocol().0 as i64),
            IpElement::Checksum => NaslValue::Number(pkt.get_checksum() as i64),
            IpElement::SourceAddress => NaslValue::String(pkt.get_source().to_string()),
            IpElement::DestinationAddress => NaslValue::String(pkt.get_destination().to_string()),
        }
    }
}

impl FromNaslValue<'_> for IpElement {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(Self::from_str(&s)?)
    }
}

/// Set element from a IP datagram. Its arguments are:
///
/// - ip: IP datagram to set fields on
/// - ip_hl: IP header length in 32 bits words, 5 by default
/// - ip_id: datagram ID, random by default
/// - ip_len: length of the datagram, 20 plus the length of the data
/// - ip_off: fragment offset in 64 bits words, 0 by default
/// - ip_p: IP protocol, 0 by default
/// - ip_src: source address in ASCII, NASL will convert it into an integer in network order
/// - ip_sum: packet header checksum, it will be computed by default
/// - ip_tos: type of service field, 0 by default
/// - ip_ttl: time to live field, 64 by default
/// - ip_v: IP version, 4 by default
///
/// Returns the modified IP datagram
#[nasl_function(named(ip, ip_hl, ip_v, ip_tos, ip_ttl, ip_id, ip_off, ip_p, ip_src, ip_sum))]
fn set_ip_elements(
    ip: &[u8],
    ip_hl: Option<u8>,
    ip_v: Option<u8>,
    ip_tos: Option<u8>,
    ip_ttl: Option<u8>,
    ip_id: Option<u16>,
    ip_off: Option<u16>,
    ip_p: Option<u8>,
    ip_src: Option<String>,
    ip_sum: Option<u16>,
) -> Result<NaslValue, FnError> {
    let mut buf = ip.to_vec();
    let mut pkt = MutableIpv4Packet::new(&mut buf).ok_or(PacketForgeryError::CreateIpv4Packet)?;

    if let Some(ip_hl) = ip_hl {
        pkt.set_header_length(ip_hl);
    };

    if let Some(ip_v) = ip_v {
        pkt.set_version(ip_v);
    };

    if let Some(ip_tos) = ip_tos {
        pkt.set_dscp(ip_tos);
    };
    if let Some(ip_ttl) = ip_ttl {
        pkt.set_ttl(ip_ttl);
    };

    if let Some(ip_id) = ip_id {
        pkt.set_identification(ip_id.to_be());
    };
    if let Some(ip_off) = ip_off {
        pkt.set_fragment_offset(ip_off);
    };

    if let Some(ip_p) = ip_p {
        pkt.set_next_level_protocol(IpNextHeaderProtocol(ip_p));
    };

    if let Some(x) = ip_src {
        match x.parse::<Ipv4Addr>() {
            Ok(ip) => {
                pkt.set_source(ip);
            }
            Err(e) => {
                return Err(ArgumentError::WrongArgument(format!("Invalid ip_src: {}", e)).into());
            }
        };
    };

    if let Some(ip_sum) = ip_sum {
        pkt.set_checksum(ip_sum.to_be());
    };

    Ok(NaslValue::Data(buf))
}

/// Get an IP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - ip: is the IP datagram.
/// - element: is the name of the field to get
///
/// Valid IP elements to get are:
/// - ip_v
/// - ip_id
/// - ip_hl
/// - ip_tos
/// - ip_len
/// - ip_off
/// - ip_ttl
/// - ip_p
/// - ip_sum
/// - ip_src
/// - ip_dst
#[nasl_function(named(ip, element))]
fn get_ip_element(ip: Ipv4Packet, element: IpElement) -> Result<NaslValue, FnError> {
    Ok(element.get_element(&ip))
}

fn dump_protocol(pkt: &Ipv4Packet) -> String {
    let protocol = pkt.get_next_level_protocol();
    let byte = protocol.to_primitive_values().0;
    let protocol_name = match protocol {
        IpNextHeaderProtocols::Tcp => "IPPROTO_TCP",
        IpNextHeaderProtocols::Udp => "IPPROTO_UDP",
        _ => "IPPROTO_ICMP",
    };
    format!("{} ({})", protocol_name, byte)
}

/// Receive a list of IP packets and print them in a readable format in the screen.
#[nasl_function]
fn dump_ip_packet(positional: CheckedPositionals<Ipv4Packet>) {
    for pkt in positional.into_iter() {
        println!("\tip_hl={}", pkt.get_header_length());
        println!("\tip_v={}", pkt.get_version());
        println!("\tip_tos={}", pkt.get_dscp());
        println!("\tip_len={}", pkt.get_total_length());
        println!("\tip_id={}", pkt.get_identification());
        println!("\tip_off={}", pkt.get_fragment_offset());
        println!("\tip_ttl={}", pkt.get_ttl());
        println!("\tip_p={}", dump_protocol(&pkt));
        println!("\tip_sum={}", pkt.get_checksum());
        println!("\tip_src={}", pkt.get_source());
        println!("\tip_dst={}", pkt.get_destination());
        display_packet(pkt.packet());
    }
}

/// Add an option to a specified IP datagram.
///
/// - ip: is the IP datagram
/// - code: is the identifier of the option to add
/// - length: is the length of the option data
/// - value: is the option data
#[nasl_function(named(ip, code, length, value))]
fn insert_ip_options(
    ip: &[u8],
    code: i64,
    length: usize,
    value: NaslValue,
) -> Result<NaslValue, FnError> {
    let buf = ip.to_vec();
    let value = match value {
        NaslValue::String(x) => x.as_bytes().to_vec(),
        NaslValue::Data(x) => x,
        _ => {
            return Err(FnError::missing_argument("value"));
        }
    };

    // The pnet library does not have the implementation for create/modify TcpOptions.
    // The TcpOption struct members are even private. Therefore, creating it manually.
    // This is not possible:
    //let opt = Ipv4Option{
    //    copied: 1,
    //    class: 0,
    //    number: Ipv4OptionNumber(3),
    //    length: opt_len.to_vec(),
    //    data: opt_buf.to_vec(),
    //};

    // Get the first byte from an i64
    let codebyte = code.to_le_bytes()[0];
    // Length is 2 bytes. Get the 2 bytes from the i64
    let opt_len = &length.to_le_bytes()[..2];
    let mut opt_buf = vec![0u8; length];

    //opt_buf[..1].copy_from_slice(&vec![codebyte][..]);
    safe_copy_from_slice(&mut opt_buf[..], 0, 1, &[codebyte], 0, 1)?;
    //opt_buf[1..3].copy_from_slice(opt_len);
    safe_copy_from_slice(&mut opt_buf[..], 1, 3, opt_len, 0, opt_len.len())?;
    //opt_buf[3..].copy_from_slice(value);
    safe_copy_from_slice(&mut opt_buf[..], 3, length, &value, 0, value.len())?;

    let hl_valid_data = 20 + opt_buf.len();
    let padding = 32 - hl_valid_data % 32;
    let hl = hl_valid_data + padding;
    let mut new_buf = vec![0u8; hl];
    //new_buf[..20].copy_from_slice(&buf[..20]);
    safe_copy_from_slice(&mut new_buf[..], 0, 20, &buf, 0, 20)?;
    //new_buf[20..hl_valid_data].copy_from_slice(&opt_buf[..opt_buf.len()]);
    safe_copy_from_slice(
        &mut new_buf[..],
        20,
        hl_valid_data,
        &opt_buf,
        0,
        opt_buf.len(),
    )?;

    let mut new_pkt = MutableIpv4Packet::new(&mut new_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    let checksum = checksum(&new_pkt.to_immutable());
    new_pkt.set_checksum(checksum);
    new_pkt.set_header_length((hl / 4) as u8);
    Ok(NaslValue::Data(new_pkt.packet().to_vec()))
}

#[allow(clippy::too_many_arguments)]
fn forge_tcp(
    data: Option<PacketPayload>,
    th_sport: Option<u16>,
    th_dport: Option<u16>,
    th_seq: Option<u32>,
    th_ack: Option<u32>,
    th_x2: Option<u8>,
    th_offset: Option<u8>,
    th_flags: Option<u16>,
    th_win: Option<u16>,
    th_urp: Option<u16>,
) -> Vec<u8> {
    let data: Vec<u8> = data.unwrap_or_default().into();
    let total_length = MIN_TCP_HEADER_LENGTH + data.len();
    let mut buf = vec![0; total_length];
    // Safe because we know the buffer size.
    let mut tcp_seg = packet::tcp::MutableTcpPacket::new(&mut buf).unwrap();

    if !data.is_empty() {
        tcp_seg.set_payload(&data);
    }
    tcp_seg.set_source(th_sport.unwrap_or(0_u16));
    tcp_seg.set_destination(th_dport.unwrap_or(0_u16));
    tcp_seg.set_sequence(th_seq.unwrap_or(random_impl().unwrap() as u32));
    tcp_seg.set_acknowledgement(th_ack.unwrap_or(0_u32));
    tcp_seg.set_reserved(th_x2.unwrap_or(0_u8));
    tcp_seg.set_data_offset(th_offset.unwrap_or(5_u8));
    tcp_seg.set_flags(th_flags.unwrap_or(0_u16));
    tcp_seg.set_window(th_win.unwrap_or(0_u16));
    tcp_seg.set_urgent_ptr(th_urp.unwrap_or(0_u16));

    tcp_seg.packet().to_vec()
}

/// Fills an IP datagram with TCP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
///
/// - data: is the TCP data payload.
/// - ip: is the IP datagram to be filled.
/// - th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
/// - th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - th_flags: are the TCP flags. 0 by default.
/// - th_off: is the size of the TCP header in 32 bits words. By default, 5.
/// - th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
/// - th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - th_sum: is the TCP checksum. By default, the right value is computed.
/// - th_urp: is the urgent pointer. 0 by default.
/// - th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
/// - th_x2: is a reserved field and should probably be left unchanged. 0 by default.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
///
/// The modified IP datagram or NULL on error.
#[nasl_function(named(
    ip,
    data,
    th_sport,
    th_dport,
    th_seq,
    th_ack,
    th_x2,
    th_off,
    th_flags,
    th_win,
    th_urp,
    th_sum,
    update_ip_len
))]
#[allow(clippy::too_many_arguments)]
fn forge_tcp_packet(
    ip: &[u8],
    data: Option<PacketPayload>,
    th_sport: Option<u16>,
    th_dport: Option<u16>,
    th_seq: Option<u32>,
    th_ack: Option<u32>,
    th_x2: Option<u8>,
    th_off: Option<u8>,
    th_flags: Option<u16>,
    th_win: Option<u16>,
    th_urp: Option<u16>,
    th_sum: Option<u16>,
    update_ip_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let original_ip_len = ip.len();
    let mut ip_buf = ip.to_vec();
    let mut tcp_buf = forge_tcp(
        data, th_sport, th_dport, th_seq, th_ack, th_x2, th_off, th_flags, th_win, th_urp,
    );

    let mut tcp_buf_aux = vec![0u8; tcp_buf.len()];
    ip_buf.append(&mut tcp_buf_aux);
    let mut pkt = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    let mut tcp_seg = MutableTcpPacket::new(&mut tcp_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    // Calculate checksum for TCP segment now, because it depends on the dst and src addresses

    let chksum = tcp_seg.calculate_checksum(th_sum, &pkt.to_immutable());
    tcp_seg.set_checksum(chksum);

    let l = original_ip_len + tcp_buf.len();
    pkt.set_total_length((l as u16).to_le());
    pkt.set_payload(&tcp_buf);

    if !update_ip_len.unwrap_or(true) {
        pkt.set_total_length(original_ip_len as u16);
    };
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
}

enum TcpElement {
    SourcePort,
    DestPort,
    Seq,
    Ack,
    X2,
    OffSet,
    Flags,
    Win,
    Checksum,
    Urp,
    Data,
}

impl FromStr for TcpElement {
    type Err = ArgumentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "th_sport" => Ok(Self::SourcePort),
            "th_dport" => Ok(Self::DestPort),
            "th_seq" => Ok(Self::Seq),
            "th_ack" => Ok(Self::Ack),
            "th_x2" => Ok(Self::X2),
            "th_off" => Ok(Self::OffSet),
            "th_flags" => Ok(Self::Flags),
            "th_win" => Ok(Self::Win),
            "th_sum" => Ok(Self::Checksum),
            "th_urp" => Ok(Self::Urp),
            "data" => Ok(Self::Data),
            s => Err(ArgumentError::WrongArgument(format!(
                "Invalid element for TCP packet: {}",
                s
            ))),
        }
    }
}

impl PacketElement for TcpElement {
    type Packet<'a> = packet::tcp::TcpPacket<'a>;

    fn get_element(&self, packet: &Self::Packet<'_>) -> NaslValue {
        match self {
            TcpElement::SourcePort => NaslValue::Number(packet.get_source() as i64),
            TcpElement::DestPort => NaslValue::Number(packet.get_destination() as i64),
            TcpElement::Seq => NaslValue::Number(packet.get_sequence() as i64),
            TcpElement::Ack => NaslValue::Number(packet.get_acknowledgement() as i64),
            TcpElement::X2 => NaslValue::Number(packet.get_reserved() as i64),
            TcpElement::OffSet => NaslValue::Number(packet.get_data_offset() as i64),
            TcpElement::Flags => NaslValue::Number(packet.get_flags() as i64),
            TcpElement::Win => NaslValue::Number(packet.get_window() as i64),
            TcpElement::Checksum => NaslValue::Number(packet.get_checksum() as i64),
            TcpElement::Urp => NaslValue::Number(packet.get_urgent_ptr() as i64),
            TcpElement::Data => NaslValue::Data(packet.payload().to_vec()),
        }
    }
}

impl FromNaslValue<'_> for TcpElement {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(TcpElement::from_str(&s)?)
    }
}

/// Get an TCP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - tcp: is the IP datagram.
/// - element: is the name of the field to get
///
/// Valid IP elements to get are:
/// - th_sport
/// - th_dsport
/// - th_seq
/// - th_ack
/// - th_x2
/// - th_off
/// - th_flags
/// - th_win
/// - th_sum
/// - th_urp
/// - data
///
/// Returns an TCP element from a IP datagram.
#[nasl_function(named(tcp, element))]
fn get_tcp_element(tcp: TcpPacket, element: TcpElement) -> Result<NaslValue, FnError> {
    Ok(element.get_element(&tcp))
}

#[derive(Debug)]
enum TcpOpt {
    MaxSeg,
    Window,
    SackPermitted,
    Timestamp,
}

impl TryFrom<i64> for TcpOpt {
    type Error = ArgumentError;

    fn try_from(opt: i64) -> Result<Self, Self::Error> {
        match opt {
            2 => Ok(Self::MaxSeg),
            3 => Ok(Self::Window),
            4 => Ok(Self::SackPermitted),
            8 => Ok(Self::Timestamp),
            opt => Err(ArgumentError::WrongArgument(format!(
                "Invalid TCP Option value: {}",
                opt
            ))),
        }
    }
}

impl FromNaslValue<'_> for TcpOpt {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let o = i64::from_nasl_value(value)?;
        Ok(TcpOpt::try_from(o)?)
    }
}

/// Get a TCP option from a IP datagram. Its arguments are:
/// - tcp: is the IP datagram.
/// - option: is the name of the field to get
///
/// Valid IP options to get are:
/// - 2: TCPOPT_MAXSEG, values between 536 and 65535
/// - 3: TCPOPT_WINDOW, with values between 0 and 14
/// - 4: TCPOPT_SACK_PERMITTED, no value required.
/// - 8: TCPOPT_TIMESTAMP, 8 bytes value for timestamp and echo timestamp, 4 bytes each one.
///
/// The returned option depends on the given *option* parameter. It is either an int for option 2, 3 and 4 or an array containing the two values for option 8.
#[nasl_function(named(tcp, option))]
fn get_tcp_option(tcp: TcpPacket, option: TcpOpt) -> Result<NaslValue, FnError> {
    let mut max_seg: i64 = 0;
    let mut window: i64 = 0;
    let mut sack_permitted: i64 = 0;
    let mut timestamps: Vec<NaslValue> = vec![NaslValue::Number(0), NaslValue::Number(0)];

    for opt in tcp.get_options_iter() {
        if opt.get_number() == TcpOptionNumbers::MSS {
            let mut val = [0u8; 2];
            //val[..2].copy_from_slice(&opt.payload()[..2]);
            safe_copy_from_slice(&mut val, 0, 2, opt.payload(), 0, 2)?;
            max_seg = i16::from_be_bytes(val) as i64;
        }
        if opt.get_number() == TcpOptionNumbers::WSCALE {
            let mut val = [0u8; 1];
            //val[..1].copy_from_slice(&opt.payload()[..1]);
            safe_copy_from_slice(&mut val, 0, 1, opt.payload(), 0, 1)?;
            window = val[0] as i64;
        }
        if opt.get_number() == TcpOptionNumbers::SACK_PERMITTED {
            sack_permitted = 1;
        }
        if opt.get_number() == TcpOptionNumbers::TIMESTAMPS {
            let mut t1 = [0u8; 4];
            let mut t2 = [0u8; 4];
            //t1[..4].copy_from_slice(&opt.payload()[..4]);
            safe_copy_from_slice(&mut t1, 0, 4, opt.payload(), 0, 4)?;
            //t2[..4].copy_from_slice(&opt.payload()[4..]);
            safe_copy_from_slice(&mut t2, 0, 4, opt.payload(), 4, opt.payload().len())?;
            let t1_val = i32::from_be_bytes(t1) as i64;
            let t2_val = i32::from_be_bytes(t2) as i64;

            timestamps = vec![NaslValue::Number(t1_val), NaslValue::Number(t2_val)];
        }
    }

    match option {
        TcpOpt::MaxSeg => Ok(NaslValue::Number(max_seg)),
        TcpOpt::Window => Ok(NaslValue::Number(window)),
        TcpOpt::SackPermitted => Ok(NaslValue::Number(sack_permitted)),
        TcpOpt::Timestamp => Ok(NaslValue::Array(timestamps)),
    }
}

#[allow(clippy::too_many_arguments)]
fn set_elements_tcp<'a>(
    ori_tcp_buf: &'a [u8],
    data: Option<PacketPayload>,
    th_sport: Option<u16>,
    th_dport: Option<u16>,
    th_seq: Option<u32>,
    th_ack: Option<u32>,
    th_x2: Option<u8>,
    th_off: Option<u8>,
    th_flags: Option<u16>,
    th_urp: Option<u16>,
    th_win: Option<u16>,
    new_buf: &'a mut Vec<u8>,
) -> Result<MutableTcpPacket<'a>, FnError> {
    let data: Vec<u8> = data.unwrap_or_default().into();
    let mut ori_tcp: MutableTcpPacket;

    let tcp_total_length: usize;
    if !data.is_empty() {
        //Prepare a new buffer with new size, copy the tcp header and set the new data
        tcp_total_length = MIN_TCP_HEADER_LENGTH + data.len();
        *new_buf = vec![0u8; tcp_total_length];
        safe_copy_from_slice(&mut new_buf[..], 0, 8, ori_tcp_buf, 0, 8)?;

        ori_tcp = MutableTcpPacket::new(new_buf)
            .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
        ori_tcp.set_payload(&data);
    } else {
        // Copy the original tcp buffer into the new buffer
        tcp_total_length = ori_tcp_buf.len();
        *new_buf = vec![0u8; tcp_total_length];

        safe_copy_from_slice(
            &mut new_buf[..],
            0,
            tcp_total_length,
            ori_tcp_buf,
            0,
            ori_tcp_buf.len(),
        )?;
        ori_tcp = MutableTcpPacket::new(new_buf)
            .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    }

    if let Some(sport) = th_sport {
        ori_tcp.set_source(sport);
    };
    if let Some(dport) = th_dport {
        ori_tcp.set_destination(dport);
    };

    if let Some(seq) = th_seq {
        ori_tcp.set_sequence(seq);
    };
    if let Some(ack) = th_ack {
        ori_tcp.set_acknowledgement(ack);
    };
    if let Some(x2) = th_x2 {
        ori_tcp.set_reserved(x2);
    };
    if let Some(off) = th_off {
        ori_tcp.set_data_offset(off);
    };

    if let Some(flags) = th_flags {
        ori_tcp.set_flags(flags);
    };
    if let Some(win) = th_win {
        ori_tcp.set_window(win);
    };

    if let Some(urp) = th_urp {
        ori_tcp.set_urgent_ptr(urp);
    };

    Ok(ori_tcp)
}

/// This function modifies the TCP fields of an IP datagram. Its arguments are:
///
/// - data: is the TCP data payload.
/// - tcp: is the IP datagram to be filled.
/// - th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
/// - th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - th_flags: are the TCP flags. 0 by default.
/// - th_off: is the size of the TCP header in 32 bits words. By default, 5.
/// - th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
/// - th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - th_sum: is the TCP checksum. By default, the right value is computed.
/// - th_urp: is the urgent pointer. 0 by default.
/// - th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
/// - th_x2: is a reserved field and should probably be left unchanged. 0 by default.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
#[nasl_function(named(
    tcp,
    data,
    th_sport,
    th_dport,
    th_seq,
    th_ack,
    th_x2,
    th_off,
    th_flags,
    th_urp,
    th_win,
    th_sum,
    update_ip_len
))]
#[allow(clippy::too_many_arguments)]
fn set_tcp_elements(
    tcp: Ipv4Packet,
    data: Option<PacketPayload>,
    th_sport: Option<u16>,
    th_dport: Option<u16>,
    th_seq: Option<u32>,
    th_ack: Option<u32>,
    th_x2: Option<u8>,
    th_off: Option<u8>,
    th_flags: Option<u16>,
    th_urp: Option<u16>,
    th_sum: Option<u16>,
    th_win: Option<u16>,
    update_ip_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let ip = tcp.to_immutable();
    let iph_len = tcp.get_header_length() as usize * 4; // the header length is given in 32-bits words
    let ori_tcp_buf = <&[u8]>::clone(&ip.payload()).to_owned();

    let mut tcp_buf: Vec<u8> = vec![0u8; 0];
    let mut ori_tcp = set_elements_tcp(
        &ori_tcp_buf,
        data,
        th_sport,
        th_dport,
        th_seq,
        th_ack,
        th_x2,
        th_off,
        th_flags,
        th_urp,
        th_win,
        &mut tcp_buf,
    )?;

    // Set the checksum for the tcp segment
    let chksum = ori_tcp.calculate_checksum(th_sum, &tcp.to_immutable());
    ori_tcp.set_checksum(chksum);

    let mut ip_buf = ip.packet().to_vec();
    let mut pkt = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    // pnet will panic if the total length set in the ip datagram
    // field does not much with the total length. Therefore, the total
    // length is set to the right one before setting the payload.
    // By default it was always updated, but if desired, the original
    // length is set again after setting the payload.
    let original_ip_len = pkt.get_total_length();
    let fin_tcp_buf = ori_tcp.packet();
    pkt.set_total_length((iph_len + fin_tcp_buf.len()) as u16);
    pkt.set_payload(fin_tcp_buf);
    if !update_ip_len.unwrap_or(true) {
        pkt.set_total_length(original_ip_len);
    };

    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

fn insert_tcp_options(
    ori_tcp_buf: &[u8],
    data: Option<PacketPayload>,
    tcp_opts: CheckedPositionals<i64>,
) -> Result<Vec<u8>, FnError> {
    let tcp = TcpPacket::new(ori_tcp_buf).ok_or_else(|| {
        error("Not possible to create a TCP packet from IP buffer payload".to_string())
    })?;
    let orig_payload = PacketPayload::from(tcp.payload().to_vec());
    // Get the new data or use the existing one.
    let data: Vec<u8> = data.unwrap_or(orig_payload).into();

    let mut opts: Vec<TcpOption> = vec![];
    let mut opts_len = 0;
    let mut opts_iter = tcp_opts.iter();
    loop {
        match opts_iter.next() {
            Some(2) => {
                if let Some(val) = opts_iter.next() {
                    let v = *val as u16;
                    opts.push(TcpOption::mss(v));
                    opts_len += 4;
                } else {
                    return Err(ArgumentError::WrongArgument(
                        "Invalid value for tcp option TCPOPT_MAXSEG".to_string(),
                    )
                    .into());
                }
            }
            Some(3) => {
                if let Some(val) = opts_iter.next() {
                    let v = *val as u8;
                    opts.push(TcpOption::wscale(v));
                    opts_len += 3;
                } else {
                    return Err(ArgumentError::WrongArgument(
                        "Invalid value for tcp option TCPOPT_WINDOW".to_string(),
                    )
                    .into());
                }
            }

            Some(4) => {
                opts.push(TcpOption::sack_perm());
                opts_len += 2;
            }
            Some(8) => {
                if let Some(val1) = opts_iter.next() {
                    if let Some(val2) = opts_iter.next() {
                        let v1 = *val1 as u32;
                        let v2 = *val2 as u32;
                        opts.push(TcpOption::timestamp(v1, v2));
                        opts_len += 10;
                    } else {
                        return Err(ArgumentError::WrongArgument(
                            "Invalid value for tcp option TCPOPT_TIMESTAMP".to_string(),
                        )
                        .into());
                    }
                } else {
                    return Err(ArgumentError::WrongArgument(
                        "Invalid value for tcp option TCPOPT_TIMESTAMP".to_string(),
                    )
                    .into());
                }
            }
            None => break,
            _ => {
                return Err(ArgumentError::WrongArgument(
                    "insert_tcp_options: invalid tcp option".to_string(),
                )
                .into());
            }
        }
    }

    // Padding for completing a 32-bit word
    if opts_len > 0 {
        //Since there are options, we add 1 for the EOL
        opts_len += 1;
        let padding = 4 - (opts_len % 4);
        for _i in 0..padding {
            opts.push(TcpOption::nop());
            opts_len += 1;
        }
    }

    assert_eq!(opts_len % 4, 0);

    //Prepare a new buffer with new size, copy the tcp header and set the new data
    let tcp_total_length = MIN_TCP_HEADER_LENGTH + opts_len + data.len();
    let mut new_buf = vec![0u8; tcp_total_length];
    //new_buf[..20].copy_from_slice(&ori_tcp_buf[..20]);
    safe_copy_from_slice(&mut new_buf[..], 0, 20, ori_tcp_buf, 0, 20)?;
    // Able to unwrap since we know the buffer size.
    let mut ori_tcp = packet::tcp::MutableTcpPacket::new(&mut new_buf).unwrap();
    // At this point, opts len is a 4bytes multiple and the offset is expressed in words of 32bits

    ori_tcp.set_data_offset(DEFAULT_TCP_DATA_OFFSET_32BIT_INCREMENTS + opts_len as u8 / 4);

    if !opts.is_empty() {
        ori_tcp.set_options(&opts);
    }
    if !data.is_empty() {
        ori_tcp.set_payload(&data);
    }

    Ok(ori_tcp.packet().to_vec())
}

/// This function adds TCP options to a IP datagram. The options are given as key value(s) pair with the positional argument list. The first positional argument is the identifier of the option, the next positional argument is the value for the option. For the option TCPOPT_TIMESTAMP (8) two values must be given.
///
/// Available options are:
///
/// - 2: TCPOPT_MAXSEG, values between 536 and 65535
/// - 3: TCPOPT_WINDOW, with values between 0 and 14
/// - 4: TCPOPT_SACK_PERMITTED, no value required.
/// - 8: TCPOPT_TIMESTAMP, 8 bytes value for timestamp and echo timestamp, 4 bytes each one.
#[nasl_function(named(tcp, data, th_sum, update_ip_len))]
fn insert_tcp_v4_options(
    tcp: &[u8],
    data: Option<PacketPayload>,
    th_sum: Option<u16>,
    update_ip_len: Option<bool>,
    tcp_opts: CheckedPositionals<i64>,
) -> Result<NaslValue, FnError> {
    let ip = Ipv4Packet::new(tcp).unwrap();
    let iph_len = ip.get_header_length() as usize * 4; // the header length is given in 32-bits words
    let ori_tcp_buf = ip.payload().to_vec();

    let mut tcp_buf = insert_tcp_options(&ori_tcp_buf, data, tcp_opts)?;
    let mut tcp_seg = MutableTcpPacket::new(&mut tcp_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    // Set the checksum for the tcp segment
    let chksum = tcp_seg.calculate_checksum(th_sum, &ip);
    tcp_seg.set_checksum(chksum);

    let mut ip_buf = ip.packet().to_vec();
    let mut buf_extension = vec![0u8; tcp_buf.len() - ori_tcp_buf.len()];
    ip_buf.append(&mut buf_extension);

    let mut pkt = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    // pnet will panic if the total length set in the ip datagram
    // field does not much with the total length. Therefore, the total
    // length is set to the right one before setting the payload.
    // By default it was always updated, but if desired, the original
    // length is set again after setting the payload.
    let original_ip_len = pkt.get_total_length();
    pkt.set_total_length((iph_len + tcp_buf.len()) as u16);
    pkt.set_payload(&tcp_buf);
    if !update_ip_len.unwrap_or(true) {
        pkt.set_total_length(original_ip_len);
    };

    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

fn display_opts(pkt: &TcpPacket) {
    for o in pkt.get_options_iter() {
        let n = o.get_number();
        let p = o.payload();
        let name = match n {
            TcpOptionNumbers::MSS => Some("MAXSEQ"),
            TcpOptionNumbers::WSCALE => Some("WINDOW"),
            TcpOptionNumbers::SACK_PERMITTED => Some("SACK_PERMITTED"),
            TcpOptionNumbers::TIMESTAMPS => Some("TIMESTAMP TSval"),
            _ => None,
        };
        if let Some(name) = name {
            println!("\t\t{}: {:?}", name, p);
        }
    }
}

fn format_flags(pkt: &TcpPacket) -> String {
    let flags = pkt.get_flags();
    let mut flag_strs = vec![];
    let mut check_flag = |flag: u9be, name: &str| {
        if flags & flag == flag {
            flag_strs.push(name.to_owned());
        }
    };
    check_flag(TcpFlags::FIN, "TH_FIN");
    check_flag(TcpFlags::SYN, "TH_SYN");
    check_flag(TcpFlags::RST, "TH_RST");
    check_flag(TcpFlags::PSH, "TH_PSH");
    check_flag(TcpFlags::ACK, "TH_ACK");
    check_flag(TcpFlags::URG, "TH_URG");
    if flag_strs.is_empty() {
        "0".into()
    } else {
        flag_strs.join("|")
    }
}

fn print_tcp_packet(tcp: &TcpPacket) {
    let th_flags = format_flags(tcp);
    println!("------\n");
    println!("\tth_sport = {}", tcp.get_source());
    println!("\tth_dport = {}", tcp.get_destination());
    println!("\tth_seq = {}", tcp.get_sequence());
    println!("\tth_ack = {}", tcp.get_acknowledgement());
    println!("\tth_x2 = {}", tcp.get_reserved());
    println!("\tth_off = {}", tcp.get_data_offset());
    println!("\tth_flags = {}", th_flags);
    println!("\tth_win = {}", tcp.get_window());
    println!("\tth_sum = {}", tcp.get_checksum());
    println!("\tth_urp = {}", tcp.get_urgent_ptr());
    println!("\tTCP Options:");
    display_opts(tcp);
}

/// Receive a list of IPv4 datagrams and print their TCP part in a readable format in the screen.
#[nasl_function]
fn dump_tcp_packet(positional: CheckedPositionals<TcpPacket>) {
    for tcp_seg in positional.iter() {
        print_tcp_packet(tcp_seg);
        display_packet(tcp_seg.packet());
    }
}

/// Fills an IP datagram with UDP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
///
/// - data: is the payload.
/// - ip: is the IP datagram to be filled.
/// - uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
/// - uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
/// Returns the modified IP datagram or NULL on error.
#[nasl_function(named(ip, data, uh_sport, uh_dport, uh_sum, uh_ulen, update_ip_len))]
fn forge_udp_packet(
    ip: &[u8],
    data: Option<PacketPayload>,
    uh_sport: Option<u16>,
    uh_dport: Option<u16>,
    uh_sum: Option<u16>,
    uh_ulen: Option<u16>,
    update_ip_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let mut ip_buf = ip.to_vec();
    let original_ip_len = ip_buf.len();

    let data: Vec<u8> = data.unwrap_or_default().into();

    //udp length + data length
    let total_length = MIN_UDP_HEADER_LENGTH + data.len();
    let mut buf = vec![0; total_length];
    let mut udp_datagram = MutableUdpPacket::new(&mut buf).unwrap();

    let mut udp_buf_aux = vec![0u8; total_length];
    ip_buf.append(&mut udp_buf_aux);

    if !data.is_empty() {
        udp_datagram.set_payload(&data);
    }

    udp_datagram.set_source(uh_sport.unwrap_or(0_u16));
    udp_datagram.set_destination(uh_dport.unwrap_or(0_u16));
    udp_datagram.set_length(uh_ulen.unwrap_or(8_u16));

    let mut pkt = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;

    let chksum = udp_datagram.calculate_checksum(uh_sum, &pkt.to_immutable());

    let mut udp_datagram = MutableUdpPacket::new(&mut buf).unwrap();
    udp_datagram.set_checksum(chksum);
    // setting the real length before setting the payload to avoid pnet to crash.
    pkt.set_total_length((original_ip_len + total_length) as u16);
    pkt.set_payload(&buf);
    if !update_ip_len.unwrap_or(true) {
        pkt.set_total_length(original_ip_len as u16);
    };
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
}

fn set_elements_udp<'a>(
    ori_udp_buf: &'a [u8],
    data: Option<PacketPayload>,
    uh_dport: Option<u16>,
    uh_sport: Option<u16>,
    uh_ulen: Option<u16>,
    new_buf: &'a mut Vec<u8>,
) -> Result<MutableUdpPacket<'a>, FnError> {
    let data: Vec<u8> = data.unwrap_or_default().into();
    let mut ori_udp: MutableUdpPacket;
    let udp_total_length: usize;
    if !data.is_empty() {
        //Prepare a new buffer with new size, copy the udp header and set the new data
        udp_total_length = MIN_UDP_HEADER_LENGTH + data.len();
        *new_buf = vec![0u8; udp_total_length];
        //new_buf[..8].copy_from_slice(&ori_udp_buf[..8]);
        safe_copy_from_slice(&mut new_buf[..], 0, 8, ori_udp_buf, 0, 8)?;

        ori_udp = MutableUdpPacket::new(new_buf)
            .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
        ori_udp.set_payload(&data);
    } else {
        // Copy the original udp buffer into the new buffer
        udp_total_length = ori_udp_buf.len();
        *new_buf = vec![0u8; udp_total_length];

        //new_buf[..].copy_from_slice(&ori_udp_buf);
        safe_copy_from_slice(
            &mut new_buf[..],
            0,
            udp_total_length,
            ori_udp_buf,
            0,
            ori_udp_buf.len(),
        )?;
        ori_udp = MutableUdpPacket::new(new_buf)
            .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    }

    if let Some(uh_sport) = uh_sport {
        ori_udp.set_source(uh_sport);
    };
    if let Some(uh_dport) = uh_dport {
        ori_udp.set_destination(uh_dport);
    };
    if let Some(uh_len) = uh_ulen {
        ori_udp.set_length(uh_len);
    };
    Ok(ori_udp)
}

/// This function modifies the UDP fields of an IP datagram. Its arguments are:
///
/// - udp: is the IP datagram to be filled.
/// - data: is the payload.
/// - uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
/// - uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
#[nasl_function(named(udp, data, uh_dport, uh_sport, uh_sum, uh_ulen))]
fn set_udp_elements(
    udp: Ipv4Packet,
    data: Option<PacketPayload>,
    uh_dport: Option<u16>,
    uh_sport: Option<u16>,
    uh_sum: Option<u16>,
    uh_ulen: Option<u16>,
) -> Result<NaslValue, FnError> {
    let ip = udp.to_immutable();
    let iph_len = ip.get_header_length() as usize * 4; // the header length is given in 32-bits words
    let ori_udp_buf = ip.payload().to_vec().clone();

    let mut udp_buf: Vec<u8> = vec![0u8; 0];
    let mut ori_udp = set_elements_udp(
        &ori_udp_buf,
        data,
        uh_dport,
        uh_sport,
        uh_ulen,
        &mut udp_buf,
    )?;

    // Set the checksum for the tcp segment
    let chksum = ori_udp.calculate_checksum(uh_sum, &udp);
    ori_udp.set_checksum(chksum);

    let mut ip_buf = ip.packet().to_vec();
    let mut pkt = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    let fin_udp_buf = ori_udp.packet();
    pkt.set_total_length((iph_len + fin_udp_buf.len()) as u16);
    pkt.set_payload(fin_udp_buf);

    // New IP checksum
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

fn dump_udp(pkt: &UdpPacket, data: &[u8]) {
    println!("------\n");
    println!("\tuh_sport: {:?}", pkt.get_source());
    println!("\tuh_dport: {:?}", pkt.get_destination());
    println!("\tuh_len: {:?}", pkt.get_length());
    println!("\tuh_sum: {:?}", pkt.get_checksum());
    display_packet(data);
}

/// Receive a list of IPv4 or IPv6 packets and print their UDP part in a readable format in the screen.
#[nasl_function]
fn dump_udp_packet(positional: CheckedPositionals<UdpPacket>) {
    for udp_datagram in positional.iter() {
        dump_udp(udp_datagram, udp_datagram.packet());
    }
}

enum UdpElement {
    SourcePort,
    DestPort,
    Length,
    Checksum,
    Data,
}

impl FromStr for UdpElement {
    type Err = ArgumentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "uh_sport" => Ok(Self::SourcePort),
            "uh_dport" => Ok(Self::DestPort),
            "uh_ulen" => Ok(Self::Length),
            "uh_sum" => Ok(Self::Checksum),
            "data" => Ok(Self::Data),
            s => Err(ArgumentError::WrongArgument(format!(
                "Invalid element for UDP packet: {}",
                s
            ))),
        }
    }
}

impl PacketElement for UdpElement {
    type Packet<'a> = packet::udp::UdpPacket<'a>;

    fn get_element(&self, packet: &Self::Packet<'_>) -> NaslValue {
        match self {
            UdpElement::SourcePort => NaslValue::Number(packet.get_source() as i64),
            UdpElement::DestPort => NaslValue::Number(packet.get_destination() as i64),
            UdpElement::Length => NaslValue::Number(packet.get_length() as i64),
            UdpElement::Checksum => NaslValue::Number(packet.get_checksum() as i64),
            UdpElement::Data => NaslValue::Data(packet.payload().to_vec()),
        }
    }
}

impl FromNaslValue<'_> for UdpElement {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(UdpElement::from_str(&s)?)
    }
}

/// Get an UDP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - udp: is the IP datagram.
/// - element: is the name of the field to get
///
/// Valid IP elements to get are:
/// - uh_sport
/// - uh_dport
/// - uh_ulen
/// - uh_sum
/// - data
#[nasl_function(named(udp, element))]
fn get_udp_element(udp: UdpPacket, element: UdpElement) -> Result<NaslValue, FnError> {
    Ok(element.get_element(&udp))
}

/// Fills an IP datagram with ICMP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
/// - *ip*: IP datagram that is updated.
/// - *data*: Payload.
/// - *icmp_cksum*: Checksum, computed by default.
/// - *icmp_code*: ICMP code. 0 by default.
/// - *icmp_id*: ICMP ID. 0 by default.
/// - *icmp_seq*: ICMP sequence number.
/// - *icmp_type*: ICMP type. 0 by default.
/// - *update_ip_len*: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.
#[nasl_function(named(
    ip,
    data,
    icmp_cksum,
    icmp_code,
    icmp_id,
    icmp_seq,
    icmp_type,
    update_ip_len
))]
fn forge_icmp_packet(
    ip: &[u8],
    data: Option<PacketPayload>,
    icmp_cksum: Option<u16>,
    icmp_code: Option<u8>,
    icmp_id: Option<i64>,
    icmp_seq: Option<i64>,
    icmp_type: Option<u8>,
    update_ip_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let mut ip_buf = ip.to_vec();
    let original_ip_len = ip_buf.len();
    let data: Vec<u8> = data.unwrap_or_default().into();
    let total_length = MIN_ICMP_HEADER_LENGTH + data.len();
    let mut buf = vec![0; total_length];
    // Safe because the buffer size is known
    let mut icmp_pkt = MutableIcmpPacket::new(&mut buf).unwrap();

    icmp_pkt.set_icmp_type(packet::icmp::IcmpType::new(
        icmp_type.unwrap_or(packet::icmp::IcmpTypes::EchoReply.0),
    ));
    // Defaults to 0 because it is the only possible code for an echo request
    icmp_pkt.set_icmp_code(packet::icmp::IcmpCode::new(icmp_code.unwrap_or(0u8)));

    if let Some(x) = icmp_id {
        safe_copy_from_slice(&mut buf, 4, 6, &x.to_le_bytes()[..], 0, 2)?;
    }

    if let Some(x) = icmp_seq {
        safe_copy_from_slice(&mut buf, 6, 8, &x.to_le_bytes()[..], 0, 2)?;
    }
    if !data.is_empty() {
        safe_copy_from_slice(
            &mut buf,
            MIN_ICMP_HEADER_LENGTH,
            total_length,
            &data[..],
            0,
            data.len(),
        )?;
    }

    let mut icmp_pkt = MutableIcmpPacket::new(&mut buf).unwrap();
    let chksum = match icmp_cksum {
        Some(x) if x != 0 => x.to_be(),
        _ => pnet::packet::icmp::checksum(&icmp_pkt.to_immutable()),
    };
    icmp_pkt.set_checksum(chksum);

    ip_buf.append(&mut buf);
    let l = ip_buf.len();
    let mut pkt = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    pkt.set_total_length(l as u16);

    if !update_ip_len.unwrap_or(true) {
        pkt.set_total_length(original_ip_len as u16);
    };

    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
}

enum IcmpElement {
    Id,
    Code,
    Type,
    Seq,
    CheckSum,
    Data,
}

impl FromStr for IcmpElement {
    type Err = ArgumentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "icmp_id" => Ok(Self::Id),
            "icmp_code" => Ok(Self::Code),
            "icmp_type" => Ok(Self::Type),
            "icmp_seq" => Ok(Self::Seq),
            "icmp_chsum" => Ok(Self::CheckSum),
            "icmp_data" => Ok(Self::Data),
            s => Err(ArgumentError::WrongArgument(format!(
                "Invalid element for ICMP packet: {}",
                s
            ))),
        }
    }
}

impl PacketElement for IcmpElement {
    type Packet<'a> = IcmpPacket<'a>;

    fn get_element(&self, packet: &Self::Packet<'_>) -> NaslValue {
        match self {
            IcmpElement::Id => {
                if packet.payload().len() >= 4 {
                    let pl = packet.payload();
                    let mut id = [0u8; 8];
                    // id[..2].copy_from_slice(&pl[..2]);
                    // It is safe to unwrap, since the destination buffer is known.
                    safe_copy_from_slice(&mut id, 0, 2, pl, 0, 2).unwrap();
                    NaslValue::Number(i64::from_le_bytes(id))
                } else {
                    NaslValue::Number(0)
                }
            }
            IcmpElement::Code => NaslValue::Number(packet.get_icmp_code().0 as i64),
            IcmpElement::Type => NaslValue::Number(packet.get_icmp_type().0 as i64),
            IcmpElement::CheckSum => NaslValue::Number(packet.get_checksum() as i64),
            IcmpElement::Seq => {
                if packet.payload().len() >= 4 {
                    let pl = packet.payload();
                    let mut seq = [0u8; 8];
                    //seq[0..2].copy_from_slice(&pl[2..4]);
                    // It is safe to unwrap, since origin and destination buffer sizes are known.
                    safe_copy_from_slice(&mut seq, 0, 2, pl, 2, 4).unwrap();
                    NaslValue::Number(i64::from_le_bytes(seq))
                } else {
                    NaslValue::Number(0)
                }
            }
            IcmpElement::Data if packet.payload().len() > 4 => {
                NaslValue::Data(packet.payload().to_vec())
            }
            _ => NaslValue::Null,
        }
    }
}

impl FromNaslValue<'_> for IcmpElement {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(IcmpElement::from_str(&s)?)
    }
}

/// Get an ICMP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - icmp: is the IP datagram (not the ICMP part only).
/// - element: is the name of the field to get
///
/// Valid ICMP elements to get are:
/// - icmp_id
/// - icmp_code
/// - icmp_type
/// - icmp_seq
/// - icmp_chsum
/// - icmp_data
#[nasl_function(named(icmp, element))]
fn get_icmp_element(icmp: IcmpPacket, element: IcmpElement) -> Result<NaslValue, FnError> {
    Ok(element.get_element(&icmp))
}

fn print_icmp_packet(pkt: &IcmpPacket) {
    println!("------");
    println!("\ticmp_id    : {}", IcmpElement::Id.get_element(pkt));
    println!("\ticmp_code  : {:?}", pkt.get_icmp_code());
    println!("\ticmp_type  : {:?}", pkt.get_icmp_type());
    println!("\ticmp_seq   : {}", IcmpElement::Seq.get_element(pkt));
    println!("\ticmp_cksum : {}", pkt.get_checksum());
    println!("\tData       : {:?}", IcmpElement::Data.get_element(pkt));
    println!("\n");
}

/// Receive a list of IPv4 ICMP packets and print them in a readable format in the screen.
#[nasl_function]
fn dump_icmp_packet(positional: CheckedPositionals<Ipv4Packet>) -> Result<NaslValue, FnError> {
    for icmp_pkt in positional.iter() {
        let pkt = IcmpPacket::new(icmp_pkt.payload())
            .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
        print_icmp_packet(&pkt);
    }
    Ok(NaslValue::Null)
}

// IGMP
//
// Due to this line in libpnet, the #[packet] macro results in a clippy lint.
// The line just tries to allow another linting rule, so disabling the `unexpected_cfg` lint
// here should be reasonably safe.
// https://github.com/libpnet/libpnet/blob/a01aa493e2ecead4c45e7322b6c5f7ab29e8a985/pnet_macros/src/decorator.rs#L1138
#[allow(unexpected_cfgs)]
pub mod igmp {
    use std::net::Ipv4Addr;

    use pnet::packet::{Packet, PrimitiveValues};
    use pnet_macros::packet;
    use pnet_macros_support::types::*;

    /// Minimum header length for ICMP Packet Header
    pub const MIN_IGMP_HEADER_LENGTH: usize = 8;

    /// Represents the "IGMP type" header field.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct IgmpType(pub u8);

    impl IgmpType {
        /// Create a new `IgmpType` instance.
        pub fn new(val: u8) -> IgmpType {
            IgmpType(val)
        }
    }

    impl PrimitiveValues for IgmpType {
        type T = (u8,);
        fn to_primitive_values(&self) -> (u8,) {
            (self.0,)
        }
    }

    /// Represents a generic IGMP packet.
    #[allow(dead_code)]
    #[packet]
    #[derive()]
    pub struct Igmp {
        #[construct_with(u8)]
        pub igmp_type: IgmpType,
        #[construct_with(u8)]
        pub igmp_timeout: u8,
        pub checksum: u16be,
        #[construct_with(u8, u8, u8, u8)]
        pub group_address: Ipv4Addr,
        #[payload]
        pub payload: Vec<u8>,
    }

    /// The enumeration of the recognized IGMP types.
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    #[allow(dead_code)]
    pub mod IgmpTypes {
        use super::IgmpType;
        /// IGMP type for "Membership Query"
        pub const MembershipQuery: IgmpType = IgmpType(0x11);
        /// IGMP type for "IGMPv1 Membership Report"
        pub const IGMPv1MembershipReport: IgmpType = IgmpType(0x12);
        /// IGMP type for "IGMPv2 Membership Report"
        pub const IGMPv2MembershipReport: IgmpType = IgmpType(0x16);
        /// IGMP type for "IGMPv3 Membership Report"
        pub const IGMPv3MembershipReport: IgmpType = IgmpType(0x22);
        /// IGMP type for Leave Group"
        pub const LeaveGroup: IgmpType = IgmpType(0x17);
        /// OpenVAS IGMP default type
        pub const Default: IgmpType = IgmpType(0x00);
    }
    /// Calculates a checksum of an ICMP packet.
    pub fn checksum(packet: &IgmpPacket) -> u16be {
        pnet::packet::util::checksum(packet.packet(), 1)
    }
}

/// Fills an IP datagram with IGMP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
/// - ip: IP datagram that is updated.
/// - data: Payload.
/// - code: IGMP code. 0 by default.
/// - group: IGMP group
/// - type: IGMP type. 0 by default.
/// - update_ip_len: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.
#[nasl_function(named(ip, data, code, group, update_ip_len))]
fn forge_igmp_packet(
    register: &Register,
    ip: &[u8],
    data: Option<PacketPayload>,
    code: Option<u8>,
    group: Option<Ipv4Addr>,
    update_ip_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let mut ip_buf = ip.to_vec();
    let original_ip_len = ip_buf.len();

    let data: Vec<u8> = data.unwrap_or_default().into();
    let total_length = igmp::MIN_IGMP_HEADER_LENGTH + data.len();
    let mut buf = vec![0; total_length];
    let mut igmp_pkt = igmp::MutableIgmpPacket::new(&mut buf).unwrap();

    // use register since type is codeword
    match register.named("type") {
        Some(ContextType::Value(NaslValue::Number(x))) => {
            igmp_pkt.set_igmp_type(igmp::IgmpType::new(*x as u8))
        }
        _ => igmp_pkt.set_igmp_type(igmp::IgmpTypes::Default),
    };
    igmp_pkt.set_igmp_timeout(code.unwrap_or(0u8));
    igmp_pkt.set_group_address(group.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)));

    if !data.is_empty() {
        igmp_pkt.set_payload(&data);
    }

    let cksum = igmp::checksum(&igmp_pkt.to_immutable());
    safe_copy_from_slice(&mut buf, 2, 4, &cksum.to_be_bytes(), 0, 2).unwrap();

    ip_buf.append(&mut buf);
    let l = ip_buf.len();
    let mut pkt =
        MutableIpv4Packet::new(&mut ip_buf).ok_or(PacketForgeryError::CreateIpv4Packet)?;
    pkt.set_total_length(l as u16);
    if !update_ip_len.unwrap_or(true) {
        pkt.set_total_length(original_ip_len as u16);
    };
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
}

fn new_raw_socket() -> Result<Socket, FnError> {
    match Socket::new_raw(
        Domain::IPV4,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    ) {
        Ok(s) => Ok(s),
        Err(e) => Err(error(format!("Not possible to create a raw socket: {}", e))),
    }
}

fn new_raw_ipv6_socket() -> Result<Socket, FnError> {
    Socket::new(
        Domain::IPV6,                      // 10
        socket2::Type::RAW,                // 3
        Some(Protocol::from(IPPROTO_RAW)), // 255
    )
    .map_err(|e| {
        error(format!(
            "new_raw_ipv6_socket: Not possible to create a raw socket: {}",
            e
        ))
    })
}

pub fn nasl_tcp_ping_shared(configs: &ScanCtx, port: Option<u16>) -> Result<NaslValue, FnError> {
    if configs.target().ip_addr().is_ipv6() {
        return nasl_tcp_v6_ping_shared(configs, port);
    }

    let rnd_tcp_port = || -> u16 { (random_impl().unwrap_or(0) % 65535 + 1024) as u16 };

    let sports_ori: Vec<u16> = vec![
        0, 0, 0, 0, 0, 1023, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0, 0, 20, 0, 25, 0, 0, 0,
    ];
    let mut sports: Vec<u16> = vec![];
    let ports = [
        139, 135, 445, 80, 22, 515, 23, 21, 6000, 1025, 25, 111, 1028, 9100, 1029, 79, 497, 548,
        5000, 1917, 53, 161, 9001, 65535, 443, 113, 993, 8080,
    ];

    for p in sports_ori.iter() {
        if *p == 0u16 {
            sports.push(rnd_tcp_port());
        } else {
            sports.push(*p);
        }
    }

    let soc = new_raw_socket()?;
    if let Err(e) = soc.set_header_included_v4(true) {
        return Err(error(format!("Not possible to create a raw socket: {}", e)));
    };

    // Get the iface name, to set the capture device.
    let target_ip = configs.target().ip_addr();
    let local_ip = get_source_ip(target_ip)?;
    let iface = get_interface_by_local_ip(local_ip)?;
    let port = port.unwrap_or(configs.get_host_open_port().unwrap_or_default());

    if islocalhost(target_ip) {
        return Ok(NaslValue::Number(1));
    }

    let mut capture_dev = match Capture::from_device(iface) {
        Ok(c) => match c.promisc(true).timeout(100).open() {
            Ok(capture) => capture,
            Err(e) => return custom_error!("send_packet: {}", e),
        },
        Err(e) => return custom_error!("send_packet: {}", e),
    };
    let filter = format!("ip and src host {}", target_ip);

    let mut ip_buf = [0u8; 40];
    let mut ip = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    ip.set_header_length(DEFAULT_IPV4_HEADER_LENGTH_32BIT_INCREMENTS);
    ip.set_fragment_offset(0); // No offeset
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_total_length(TOTAL_TCP_HEADER_LENGTH);
    ip.set_version(IpNextHeaderProtocols::Ipv4.0);
    ip.set_dscp(0);
    ip.set_identification(random_impl()? as u16);
    ip.set_ttl(DEFAULT_TTL);
    let ipv4_src = Ipv4Addr::from_str(&local_ip.to_string())
        .map_err(|_| ArgumentError::WrongArgument("invalid IP".to_string()))?;
    ip.set_source(ipv4_src);
    let ipv4_dst = Ipv4Addr::from_str(&target_ip.to_string())
        .map_err(|_| ArgumentError::WrongArgument("invalid IP".to_string()))?;

    ip.set_destination(ipv4_dst);
    let chksum = checksum(&ip.to_immutable());
    ip.set_checksum(chksum);

    let mut tcp_buf = [0u8; 20];
    let mut tcp = MutableTcpPacket::new(&mut tcp_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    tcp.set_flags(0x02); //TH_SYN
    tcp.set_sequence(random_impl()? as u32);
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(5);
    tcp.set_window(2048);
    tcp.set_urgent_ptr(0);

    for (i, _) in sports.iter().enumerate() {
        let mut sport = rnd_tcp_port();
        let mut dport = port;
        if port == 0 {
            sport = sports[i];
            dport = ports[i] as u16;
        }

        tcp.set_source(sport);
        tcp.set_destination(dport);
        let chksum = tcp.calculate_checksum(None, &ip.to_immutable());
        tcp.set_checksum(chksum);

        ip.set_payload(tcp.packet());

        let sockaddr = socket2::SockAddr::from(SocketAddr::new(target_ip, 0));
        match soc.send_to(ip.packet(), &sockaddr) {
            Ok(b) => {
                debug!("Sent {} bytes", b);
            }
            Err(e) => {
                return Err(error(format!("send_packet: {}", e)));
            }
        }

        let p = match capture_dev.filter(&filter, true) {
            Ok(_) => capture_dev.next_packet(),
            Err(e) => Err(pcap::Error::PcapError(e.to_string())),
        };

        if p.is_ok() {
            return Ok(NaslValue::Number(1));
        }
    }

    Ok(NaslValue::Null)
}

/// This function tries to open a TCP connection and sees if anything comes back (SYN/ACK or RST).
///
/// Its argument is:
/// - port: port for the ping
#[nasl_function(named(port))]
pub fn nasl_tcp_ping(configs: &ScanCtx, port: Option<u16>) -> Result<NaslValue, FnError> {
    nasl_tcp_ping_shared(configs, port)
}

/// Send a list of packets, passed as unnamed arguments, with the option to listen to the answers.
///
/// The arguments are:
/// - Any number of packets to send
/// - length: default length of each every packet, if a packet does not fit, its actual size is taken instead
/// - pcap_active: option to capture the answers, TRUE by default
/// - pcap_filter: BPF filter used for the answers
/// - pcap_timeout: time to wait for the answers in seconds, 5 by default
/// - allow_broadcast: default FALSE
#[nasl_function(named(length, pcap_active, pcap_filter, pcap_timeout, allow_broadcast))]
fn nasl_send_packet(
    configs: &ScanCtx,
    length: Option<i32>,
    pcap_active: Option<bool>,
    pcap_filter: Option<String>,
    pcap_timeout: Option<i32>,
    allow_broadcast: Option<bool>,
    positional: CheckedPositionals<Ipv4Packet>,
) -> Result<NaslValue, FnError> {
    let use_pcap = pcap_active.unwrap_or(true);
    let filter = pcap_filter.unwrap_or_default();
    let timeout = pcap_timeout.unwrap_or(DEFAULT_TIMEOUT) * 1000;
    let mut allow_broadcast = allow_broadcast.unwrap_or(false);

    if positional.is_empty() {
        return Ok(NaslValue::Null);
    }

    let soc = new_raw_socket()?;

    if let Err(e) = soc.set_header_included_v4(true) {
        return Err(error(format!("Not possible to create a raw socket: {}", e)));
    };

    let _dflt_packet_sz = length.unwrap_or_default();

    // Get the iface name, to set the capture device.
    let target_ip = configs.target().ip_addr();
    let local_ip = get_source_ip(target_ip)?;
    let iface = get_interface_by_local_ip(local_ip)?;

    let mut capture_dev = match Capture::from_device(iface) {
        Ok(c) => match c.promisc(true).timeout(timeout).open() {
            Ok(capture) => capture,
            Err(e) => return custom_error!("send_packet: {}", e),
        },
        Err(e) => return custom_error!("send_packet: {}", e),
    };

    for packet in positional.iter() {
        if allow_broadcast {
            if let Err(err) = soc.set_broadcast(true) {
                return custom_error!("Not possible to set broadcast soc option: {}", err);
            }
            // We allow broadcast, only if the dst ip inside the packet is the broadcast
            allow_broadcast = packet.get_destination().is_broadcast();
        }

        // No broadcast destination and dst ip address inside the IP packet
        // differs from target IP, is consider a malicious or buggy script.
        if packet.get_destination() != target_ip && !allow_broadcast {
            return Err(error(format!(
                "send_packet: malicious or buggy script is trying to send packet to {} instead of designated target {}",
                packet.get_destination(),
                target_ip
            )));
        }

        let sock_str = format!("{}:{}", &packet.get_destination().to_string().as_str(), 0);
        let sockaddr =
            SocketAddr::from_str(&sock_str).map_err(PacketForgeryError::ParseSocketAddr)?;
        let sockaddr = socket2::SockAddr::from(sockaddr);

        match soc.send_to(packet.packet(), &sockaddr) {
            Ok(b) => {
                debug!("Sent {} bytes", b);
            }
            Err(e) => {
                return Err(PacketForgeryError::SendPacket(e).into());
            }
        }

        if use_pcap {
            let p = match capture_dev.filter(&filter, true) {
                Ok(_) => capture_dev.next_packet(),
                Err(e) => Err(pcap::Error::PcapError(e.to_string())),
            };

            match p {
                Ok(packet) => return Ok(NaslValue::Data(packet.data.to_vec())),
                Err(_) => return Ok(NaslValue::Null),
            };
        }
    }
    Ok(NaslValue::Null)
}

/// Read the next packet.
///
/// - interface: network interface name, by default NASL will try to find the best one
/// - pcap_filter: BPF filter, by default it listens to everything
/// - timeout: timeout in seconds, 5 by default
#[nasl_function(named(interface, pcap_filter, timeout))]
fn nasl_send_capture(
    configs: &ScanCtx,
    interface: Option<String>,
    pcap_filter: Option<String>,
    timeout: Option<i32>,
) -> Result<NaslValue, FnError> {
    let interface = interface.unwrap_or_default();
    let filter = pcap_filter.unwrap_or_default();
    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT) * 1000;

    // Get the iface name, to set the capture device.
    let target_ip = configs.target().ip_addr();
    let local_ip = get_source_ip(target_ip)?;
    let mut iface = get_interface_by_local_ip(local_ip)?;
    if !interface.is_empty() {
        iface = pcap::Device::from(interface.as_str());
    }

    let mut capture_dev = match Capture::from_device(iface) {
        Ok(c) => match c.promisc(true).timeout(timeout).open() {
            Ok(capture) => capture,
            Err(e) => return custom_error!("send_capture: {}", e),
        },
        Err(e) => return custom_error!("send_capture: {}", e),
    };

    let p = match capture_dev.filter(&filter, true) {
        Ok(_) => capture_dev.next_packet(),
        Err(e) => Err(pcap::Error::PcapError(e.to_string())),
    };

    match p {
        Ok(packet) => {
            // Remove all from lower layer
            let frame = EthernetPacket::new(packet.data)
                .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
            Ok(NaslValue::Data(frame.payload().to_vec()))
        }
        Err(_) => Ok(NaslValue::Null),
    }
}

// IP v6 functions

/// Forge an IP datagram inside the block of data. It takes following arguments:
///
/// The arguments are:
/// - data: Data payload
/// - ip6_v: Version. 6 by default.
/// - ip6_tc: Traffic class. 0 by default.
/// - ip6_fl: Flow label. 0 by default.
/// - ip6_p: IP protocol. 0 by default.
/// - ip6_hlim: Hop limit. Max. 255. 64 by default.
/// - ip6_src: Source address.
/// - ip6_dst: Destination address.
///
/// Return an IPv6 datagram or Null on error.
#[nasl_function(named(data, ip6_v, ip6_tc, ip6_fl, ip6_p, ip6_hlim, ip6_src, ip6_dst))]
fn forge_ip_v6_packet(
    configs: &ScanCtx,
    data: Option<PacketPayload>,
    ip6_v: Option<u8>,
    ip6_tc: Option<u8>,
    ip6_fl: Option<u32>,
    ip6_p: Option<u8>,
    ip6_hlim: Option<u8>,
    ip6_src: Option<Ipv6Addr>,
    ip6_dst: Option<Ipv6Addr>,
) -> Result<NaslValue, FnError> {
    let dst_addr = configs.target().ip_addr();
    if !dst_addr.is_ipv6() {
        return Err(FnError::wrong_unnamed_argument(
            "IPv6",
            "forge_ip_v6_packet: No valid dst_addr could be determined via call to get_host_ip()",
        ));
    }

    let data: Vec<u8> = data.unwrap_or_default().into();
    let total_length = FIX_IPV6_HEADER_LENGTH + data.len();
    let mut buf = vec![0; total_length];
    let mut pkt = packet::ipv6::MutableIpv6Packet::new(&mut buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;

    pkt.set_payload_length(data.len() as u16);

    if !data.is_empty() {
        pkt.set_payload(&data);
    }

    pkt.set_version(ip6_v.unwrap_or(IPPROTO_IPV6));
    pkt.set_traffic_class(ip6_tc.unwrap_or_default());
    pkt.set_flow_label(ip6_fl.unwrap_or_default());
    pkt.set_next_header(IpNextHeaderProtocol::new(ip6_p.unwrap_or_default()));
    pkt.set_hop_limit(ip6_hlim.unwrap_or(64));
    if let Some(ipsrc) = ip6_src {
        pkt.set_source(ipsrc);
    }
    if let Some(ipdst) = ip6_dst {
        pkt.set_destination(ipdst);
    } else {
        match dst_addr.to_string().parse::<Ipv6Addr>() {
            Ok(ip) => {
                pkt.set_destination(ip);
            }
            Err(e) => {
                return Err(ArgumentError::WrongArgument(format!("Invalid ip: {}", e)).into());
            }
        };
    };

    // There is no checksum for ipv6. Only upper layer
    // calculates a checksum using pseudoheader
    Ok(NaslValue::Data(buf))
}

enum Ipv6Element {
    Version,
    Traffic,
    Flow,
    Plen,
    Next,
    Hlim,
    Source,
    Destination,
}

impl FromStr for Ipv6Element {
    type Err = ArgumentError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ip6_v" => Ok(Ipv6Element::Version),
            "ip6_tc" => Ok(Ipv6Element::Traffic),
            "ip6_fl" => Ok(Ipv6Element::Flow),
            "ip6_plen" => Ok(Ipv6Element::Plen),
            "ip6_nxt" => Ok(Ipv6Element::Next),
            "ip6_hlim" => Ok(Ipv6Element::Hlim),
            "ip6_src" => Ok(Ipv6Element::Source),
            "ip6_dst" => Ok(Ipv6Element::Destination),
            s => Err(ArgumentError::WrongArgument(format!(
                "Invalid element for IPv6 packet: {}",
                s
            ))),
        }
    }
}

impl PacketElement for Ipv6Element {
    type Packet<'a> = Ipv6Packet<'a>;
    fn get_element(&self, pkt: &Self::Packet<'_>) -> NaslValue {
        match self {
            Ipv6Element::Version => NaslValue::Number(pkt.get_version() as i64),
            Ipv6Element::Traffic => NaslValue::Number(pkt.get_traffic_class() as i64),
            Ipv6Element::Flow => NaslValue::Number(pkt.get_flow_label() as i64),
            Ipv6Element::Plen => NaslValue::Number(pkt.get_payload_length() as i64),
            Ipv6Element::Next => NaslValue::Number(pkt.get_next_header().0 as i64),
            Ipv6Element::Hlim => NaslValue::Number(pkt.get_hop_limit() as i64),
            Ipv6Element::Source => NaslValue::String(pkt.get_source().to_string()),
            Ipv6Element::Destination => NaslValue::String(pkt.get_destination().to_string()),
        }
    }
}

impl FromNaslValue<'_> for Ipv6Element {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(Self::from_str(&s)?)
    }
}

/// Get an IP element from a IP v6 datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - ip6: is the IP v6 datagram.
/// - element: is the name of the field to get
///
/// Valid IP elements to get are:
/// - ip6_v
/// - ip6_tc
/// - ip6_fl
/// - ip6_plen
/// - ip6_nxt
/// - ip6_hlim
/// - ip6_src
/// - ip6_dst
#[nasl_function(named(ip6, element))]
fn get_ip_v6_element(ip6: Ipv6Packet, element: Ipv6Element) -> Result<NaslValue, FnError> {
    Ok(element.get_element(&ip6))
}

/// Set an IP element from a IP v6 datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - ip6: is the IP v6 datagram.
/// - ip6_plen
/// - ip6_nxt
/// - ip6_hlim
/// - ip6_src
#[nasl_function(named(ip6, ip6_plen, ip6_nxt, ip6_hlim, ip6_src))]
fn set_ip_v6_elements(
    ip6: &[u8],
    ip6_plen: Option<u16>,
    ip6_nxt: Option<u8>,
    ip6_hlim: Option<u8>,
    ip6_src: Option<Ipv6Addr>,
) -> Result<NaslValue, FnError> {
    let mut buf = ip6.to_vec();
    let mut pkt = packet::ipv6::MutableIpv6Packet::new(&mut buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;

    pkt.set_payload_length(ip6_plen.unwrap_or_default());
    pkt.set_hop_limit(ip6_hlim.unwrap_or_default());
    pkt.set_next_header(IpNextHeaderProtocol::new(ip6_nxt.unwrap_or_default()));

    if let Some(addr) = ip6_src {
        pkt.set_source(addr);
    };

    Ok(NaslValue::Data(pkt.to_immutable().packet().to_vec()))
}

/// Adds an IPv6 option to the datagram.
///
/// - ip6     IPv6 packet.
/// - data    Data payload.
/// - code    Code of option.
/// - length  Length of value.
/// - value   Value of the option.
///
/// Return the modified datagram.
///
#[nasl_function(named(ip6, code, length, value))]
fn insert_ip_v6_options(
    ip6: &[u8],
    code: Option<i64>,
    length: Option<usize>,
    value: Option<NaslValue>,
) -> Result<NaslValue, FnError> {
    let buf = ip6.to_vec();

    let value = match value {
        Some(NaslValue::String(x)) => x.as_bytes().to_vec(),
        Some(NaslValue::Data(x)) => x,
        _ => {
            return Err(FnError::missing_argument("value"));
        }
    };
    // The pnet library does not have the implementation for create/modify TcpOptions.
    // The TcpOption struct members are even private. Therefore, creating it manually.
    // This is not possible:
    //let opt = Ipv4Option{
    //    copied: 1,
    //    class: 0,
    //    number: Ipv4OptionNumber(3),
    //    length: opt_len.to_vec(),
    //    data: opt_buf.to_vec(),
    //};

    // Get the first byte from an i64
    let codebyte = code.unwrap_or_default().to_le_bytes()[0];
    // Length is 2 bytes. Get the 2 bytes from the i64
    let opt_len = &length.unwrap_or_default().to_le_bytes()[..2];
    let mut opt_buf = vec![0u8; length.unwrap_or_default()];

    //opt_buf[..1].copy_from_slice(&vec![codebyte][..]);
    safe_copy_from_slice(&mut opt_buf[..], 0, 1, &[codebyte], 0, 1)?;
    //opt_buf[1..3].copy_from_slice(opt_len);
    safe_copy_from_slice(&mut opt_buf[..], 1, 3, opt_len, 0, opt_len.len())?;
    //opt_buf[3..].copy_from_slice(value);
    safe_copy_from_slice(
        &mut opt_buf[..],
        3,
        length.unwrap_or_default(),
        &value,
        0,
        value.len(),
    )?;

    let hl_valid_data = FIX_IPV6_HEADER_LENGTH + opt_buf.len();
    let padding = 32 - hl_valid_data % 32;
    let hl = hl_valid_data + padding;
    let mut new_buf = vec![0u8; hl];
    //new_buf[..40].copy_from_slice(&buf[..40]);
    safe_copy_from_slice(&mut new_buf[..], 0, 40, &buf, 0, 40)?;
    //new_buf[40..hl_valid_data].copy_from_slice(&opt_buf[..opt_buf.len()]);
    safe_copy_from_slice(
        &mut new_buf[..],
        40,
        hl_valid_data,
        &opt_buf,
        0,
        opt_buf.len(),
    )?;

    let mut new_pkt = MutableIpv6Packet::new(&mut new_buf).unwrap();
    new_pkt.set_payload_length((hl / 4) as u16);
    Ok(NaslValue::Data(new_pkt.packet().to_vec()))
}

fn display_ipv6_next_header_protocol(pkt: &Ipv6Packet) {
    match pkt.get_next_header() {
        IpNextHeaderProtocols::Tcp => println!(
            "\tip6_nxt   : IPPROTO_TCP ({:?})",
            pkt.get_next_header().to_primitive_values().0
        ),
        IpNextHeaderProtocols::Udp => println!(
            "\tip6_nxt   : IPPROTO_UDP ({:?})",
            pkt.get_next_header().to_primitive_values().0
        ),
        IpNextHeaderProtocols::Icmpv6 => println!(
            "\tip6_nxt   : IPPROTO_ICMP ({:?})",
            pkt.get_next_header().to_primitive_values().0
        ),
        _ => println!(
            "\tip6_nxt   : {:?}",
            pkt.get_next_header().to_primitive_values().0
        ),
    };
}
/// Receive a list of IP v6 packets and print them in a readable format in the screen.
#[nasl_function]
fn dump_ip_v6_packet(positional: CheckedPositionals<Ipv6Packet>) {
    for pkt in positional.into_iter() {
        println!("------\n");
        println!("\tip6_v  : {:?}", pkt.get_version());
        println!("\tip6_tc   : {:?}", pkt.get_traffic_class());
        println!("\tip6_fl : {:?}", pkt.get_flow_label());
        println!("\tip6_plen : {:?}", pkt.get_payload_length());
        println!("\tip6_hlim  : {:?}", pkt.get_hop_limit());
        display_ipv6_next_header_protocol(&pkt);
        println!("\tip6_src : {:?}", pkt.get_source().to_string());
        println!("\tip6_dst : {:?}", pkt.get_destination().to_string());
        display_packet(pkt.packet());
    }
}

// TCP over IPv6

/// Fills an IP datagram with TCP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
///
/// - ip6: is the IP datagram to be filled.
/// - data: is the TCP data payload.
/// - th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
/// - th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
/// - th_x2: is a reserved field and should probably be left unchanged. 0 by default.
/// - th_off: is the size of the TCP header in 32 bits words. By default, 5.
/// - th_flags: are the TCP flags. 0 by default.
/// - th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
/// - th_sum: is the TCP checksum. By default, the right value is computed.
/// - th_urp: is the urgent pointer. 0 by default.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
///
/// The modified IP datagram or NULL on error.
#[nasl_function(named(
    ip6, data, th_sport, th_dport, th_seq, th_ack, th_x2, th_off, th_flags, th_win, th_urp, th_sum,
))]
fn forge_tcp_v6_packet(
    ip6: &[u8],
    data: Option<PacketPayload>,
    th_sport: Option<u16>,
    th_dport: Option<u16>,
    th_seq: Option<u32>,
    th_ack: Option<u32>,
    th_x2: Option<u8>,
    th_off: Option<u8>,
    th_flags: Option<u16>,
    th_win: Option<u16>,
    th_urp: Option<u16>,
    th_sum: Option<u16>,
) -> Result<NaslValue, FnError> {
    let mut ip_buf = ip6.to_vec();
    let mut tcp_buf = forge_tcp(
        data, th_sport, th_dport, th_seq, th_ack, th_x2, th_off, th_flags, th_win, th_urp,
    );

    // extend ip buf.
    let mut tcp_buf_aux = vec![0u8; tcp_buf.len()];
    ip_buf.append(&mut tcp_buf_aux);

    let mut pkt = packet::ipv6::MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    let mut tcp_seg = MutableTcpPacket::new(&mut tcp_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;

    // Calculate checksum for TCP segment now, because it depends on the dst and src addresses
    let chksum = tcp_seg.calculate_checksum(th_sum, &pkt.to_immutable());
    tcp_seg.set_checksum(chksum);

    pkt.set_payload_length(tcp_buf.len() as u16);
    pkt.set_payload(&tcp_buf);
    Ok(NaslValue::Data(ip_buf))
}

/// This function modifies the TCP fields of an IP datagram. Its arguments are:
///
/// - data: is the TCP data payload.
/// - tcp: is the IP datagram to be filled.
/// - th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
/// - th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - th_flags: are the TCP flags. 0 by default.
/// - th_off: is the size of the TCP header in 32 bits words. By default, 5.
/// - th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
/// - th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - th_sum: is the TCP checksum. By default, the right value is computed.
/// - th_urp: is the urgent pointer. 0 by default.
/// - th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
/// - th_x2: is a reserved field and should probably be left unchanged. 0 by default.
/// - update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
#[nasl_function(named(
    tcp,
    data,
    th_sport,
    th_dport,
    th_seq,
    th_ack,
    th_x2,
    th_off,
    th_flags,
    th_urp,
    th_win,
    th_sum,
    update_ip_len
))]
fn set_tcp_v6_elements(
    tcp: Ipv6Packet,
    data: Option<PacketPayload>,
    th_sport: Option<u16>,
    th_dport: Option<u16>,
    th_seq: Option<u32>,
    th_ack: Option<u32>,
    th_x2: Option<u8>,
    th_off: Option<u8>,
    th_flags: Option<u16>,
    th_urp: Option<u16>,
    th_sum: Option<u16>,
    th_win: Option<u16>,
    update_ip_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let ip = tcp.to_immutable();
    let payload_len = tcp.get_payload_length() as usize * 4; // the tcp segment length is given in 32-bits words
    let ori_tcp_buf = <&[u8]>::clone(&ip.payload()).to_owned();

    let mut tcp_buf: Vec<u8> = vec![0u8; 0];
    let mut ori_tcp = set_elements_tcp(
        &ori_tcp_buf,
        data,
        th_sport,
        th_dport,
        th_seq,
        th_ack,
        th_x2,
        th_off,
        th_flags,
        th_urp,
        th_win,
        &mut tcp_buf,
    )?;

    // Set the checksum for the tcp segment
    let chksum = ori_tcp.calculate_checksum(th_sum, &tcp.to_immutable());
    ori_tcp.set_checksum(chksum);

    let mut ip_buf = ip.packet().to_vec();
    let mut pkt = MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    // pnet will panic if the total length set in the ip datagram field does not much with the total length.
    // Therefore, the total length is set to the right one before setting the payload.
    // By default it was always updated, but if desired, the original length is set again after setting the payload.
    let fin_tcp_buf = ori_tcp.packet();
    pkt.set_payload_length(fin_tcp_buf.len() as u16);
    pkt.set_payload(fin_tcp_buf);
    if !update_ip_len.unwrap_or(true) {
        pkt.set_payload_length(payload_len as u16);
    };

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

/// This function adds TCP options to a IP datagram. The options are given as key value(s) pair with the positional argument list. The first positional argument is the identifier of the option, the next positional argument is the value for the option. For the option TCPOPT_TIMESTAMP (8) two values must be given.
///
/// Available options are:
///
/// - 2: TCPOPT_MAXSEG, values between 536 and 65535
/// - 3: TCPOPT_WINDOW, with values between 0 and 14
/// - 4: TCPOPT_SACK_PERMITTED, no value required.
/// - 8: TCPOPT_TIMESTAMP, 8 bytes value for timestamp and echo timestamp, 4 bytes each one.
#[nasl_function(named(tcp, data, th_sum, update_ip_len))]
fn insert_tcp_v6_options(
    tcp: &[u8],
    data: Option<PacketPayload>,
    th_sum: Option<u16>,
    update_ip_len: Option<bool>,
    tcp_opts: CheckedPositionals<i64>,
) -> Result<NaslValue, FnError> {
    let ip = Ipv6Packet::new(tcp).unwrap();
    let payload_len = ip.get_payload_length();
    let ori_tcp_buf = ip.payload().to_vec();

    let mut tcp_buf = insert_tcp_options(&ori_tcp_buf, data, tcp_opts)?;
    let mut tcp_seg = MutableTcpPacket::new(&mut tcp_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    // Set the checksum for the tcp segment
    let chksum = tcp_seg.calculate_checksum(th_sum, &ip.to_immutable());
    tcp_seg.set_checksum(chksum);

    let mut ip_buf = ip.packet().to_vec();
    let mut buf_extension = vec![0u8; tcp_buf.len() - ori_tcp_buf.len()];
    ip_buf.append(&mut buf_extension);
    let mut pkt = MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    // pnet will panic if the total length set in the ip datagram field does not much with the total length.
    // Therefore, the total length is set to the right one before setting the payload.
    // By default it was always updated, but if desired, the original length is set again after setting the payload.
    pkt.set_payload_length(tcp_buf.len() as u16);
    pkt.set_payload(&tcp_buf);
    if !update_ip_len.unwrap_or(true) {
        pkt.set_payload_length(payload_len);
    };

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

/// Receive a list of IPv6 datagrams and print their TCP part in a readable format in the screen.
#[nasl_function]
fn dump_tcp_v6_packet(positional: CheckedPositionals<TcpPacket>) {
    for tcp_seg in positional.iter() {
        print_tcp_packet(tcp_seg);
        display_packet(tcp_seg.packet());
    }
}

// UDP over IPv6

/// Fills an IP v6 packet with UDP datagram. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
///
/// - data: is the payload.
/// - ip6: is the IP datagram to be filled.
/// - uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
/// - uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
/// - update_ip6_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
/// Returns the modified IP datagram or NULL on error.
#[nasl_function(named(ip6, data, uh_sport, uh_dport, uh_sum, uh_ulen, update_ip6_len))]
fn forge_udp_v6_packet(
    ip6: &[u8],
    data: Option<PacketPayload>,
    uh_sport: Option<u16>,
    uh_dport: Option<u16>,
    uh_sum: Option<u16>,
    uh_ulen: Option<u16>,
    update_ip6_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let mut ip_buf = ip6.to_vec();
    let original_ip_len = ip_buf.len();

    let data: Vec<u8> = data.unwrap_or_default().into();

    //udp length + data length
    let total_length = MIN_UDP_HEADER_LENGTH + data.len();
    let mut buf = vec![0; total_length];
    let mut udp_datagram = MutableUdpPacket::new(&mut buf).unwrap();

    // extend ip buf.
    let mut udp_buf_aux = vec![0u8; total_length];
    ip_buf.append(&mut udp_buf_aux);

    if !data.is_empty() {
        udp_datagram.set_payload(&data);
    }

    udp_datagram.set_source(uh_sport.unwrap_or(0_u16));
    udp_datagram.set_destination(uh_dport.unwrap_or(0_u16));
    udp_datagram.set_length(uh_ulen.unwrap_or(8_u16));

    let mut pkt = MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    let chksum = udp_datagram.calculate_checksum(uh_sum, &pkt.to_immutable());

    let mut udp_datagram = MutableUdpPacket::new(&mut buf).unwrap();
    udp_datagram.set_checksum(chksum);

    pkt.set_payload_length(buf.len() as u16);
    pkt.set_payload(&buf);
    if !update_ip6_len.unwrap_or(false) {
        pkt.set_payload_length(original_ip_len as u16);
    };

    Ok(NaslValue::Data(ip_buf))
}

/// This function modifies the UDP fields of an IPv6 packet. Its arguments are:
///
/// - udp: is the IP v6 packet to be filled.
/// - data: is the payload.
/// - uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
/// - uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
#[nasl_function(named(udp, data, uh_dport, uh_sport, uh_sum, uh_ulen))]
fn set_udp_v6_elements(
    udp: Ipv6Packet,
    data: Option<PacketPayload>,
    uh_dport: Option<u16>,
    uh_sport: Option<u16>,
    uh_sum: Option<u16>,
    uh_ulen: Option<u16>,
) -> Result<NaslValue, FnError> {
    let ip = udp.to_immutable();
    let ori_udp_buf = ip.payload().to_vec().clone();

    let mut udp_buf: Vec<u8> = vec![0u8; 0];
    let mut ori_udp = set_elements_udp(
        &ori_udp_buf,
        data,
        uh_dport,
        uh_sport,
        uh_ulen,
        &mut udp_buf,
    )?;
    // Set the checksum for the tcp segment
    let chksum = ori_udp.calculate_checksum(uh_sum, &udp.to_immutable());
    ori_udp.set_checksum(chksum);

    let mut ip_buf = ip.packet().to_vec();
    let mut pkt = MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    let fin_udp_buf = ori_udp.packet();
    pkt.set_payload(fin_udp_buf);
    pkt.set_payload_length(fin_udp_buf.len() as u16);

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

// ICMP6

/// Fills an IPv6 packet with ICMPv6 data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are,
/// - ip6: IP datagram that is updated.
/// - data: Payload.
/// - icmp_cksum: Checksum, computed by default.
/// - icmp_code: ICMP code. 0 by default.
/// - icmp_id: ICMP ID. 0 by default.
/// - icmp_seq: ICMP sequence number.
/// - icmp_type: ICMP type. 0 by default.
/// - reachable_time:
/// - retransmit_time:
/// - flags:
/// - target:
/// - update_ip_len: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.
#[nasl_function(named(
    ip6,
    data,
    icmp_cksum,
    icmp_code,
    icmp_id,
    icmp_seq,
    icmp_type,
    reachable_time,
    retransmit_time,
    flags,
    target,
    update_ip_len
))]
fn forge_icmp_v6_packet(
    ip6: &[u8],
    data: Option<PacketPayload>,
    icmp_cksum: Option<u8>,
    icmp_code: Option<u8>,
    icmp_id: Option<i32>,
    icmp_seq: Option<i64>,
    icmp_type: u8,
    reachable_time: Option<u32>,
    retransmit_time: Option<u32>,
    flags: Option<u8>,
    target: Option<Ipv6Addr>,
    update_ip_len: Option<bool>,
) -> Result<NaslValue, FnError> {
    let mut ip_buf = ip6.to_vec();
    let original_ip_len = ip_buf.len();
    let pkt = MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;

    let data: Vec<u8> = data.unwrap_or_default().into();
    let icmp_code = Icmpv6Code::new(icmp_code.unwrap_or(0u8));
    let icmp_type = packet::icmpv6::Icmpv6Type::new(icmp_type);
    let icmp_pkt_size = match icmp_type {
        Icmpv6Types::EchoRequest => MutableEchoRequestPacket::minimum_packet_size(),
        Icmpv6Types::RouterSolicit => MutableRouterSolicitPacket::minimum_packet_size(),
        Icmpv6Types::RouterAdvert => MutableRouterAdvertPacket::minimum_packet_size(),
        Icmpv6Types::NeighborSolicit => MutableNeighborAdvertPacket::minimum_packet_size(),
        Icmpv6Types::NeighborAdvert => MutableNeighborAdvertPacket::minimum_packet_size(),
        _ => MIN_ICMP_HEADER_LENGTH,
    };
    let total_length = icmp_pkt_size + data.len();
    let mut icmp_buf = vec![0; total_length];
    match icmp_type {
        Icmpv6Types::EchoRequest => {
            let mut icmp_pkt = packet::icmpv6::MutableIcmpv6Packet::new(&mut icmp_buf).unwrap();

            icmp_pkt.set_icmpv6_type(icmp_type);
            icmp_pkt.set_icmpv6_code(icmp_code);

            if !data.is_empty() {
                safe_copy_from_slice(&mut icmp_buf, 8, total_length, &data[..], 0, data.len())?;
            }

            if let Some(x) = icmp_id {
                safe_copy_from_slice(&mut icmp_buf, 4, 6, &x.to_le_bytes()[..], 0, 2)?;
            }

            if let Some(x) = icmp_seq {
                safe_copy_from_slice(&mut icmp_buf, 6, 8, &x.to_le_bytes()[..], 0, 2)?;
            }
        }
        Icmpv6Types::RouterSolicit => {
            let mut icmp_pkt =
                packet::icmpv6::ndp::MutableRouterSolicitPacket::new(&mut icmp_buf).unwrap();

            icmp_pkt.set_icmpv6_type(icmp_type);
            icmp_pkt.set_icmpv6_code(icmp_code);

            if !data.is_empty() {
                safe_copy_from_slice(&mut icmp_buf, 8, total_length, &data[..], 0, data.len())?;
            }
        }
        Icmpv6Types::RouterAdvert => {
            let mut icmp_pkt = MutableRouterAdvertPacket::new(&mut icmp_buf).unwrap();

            icmp_pkt.set_icmpv6_type(icmp_type);
            icmp_pkt.set_icmpv6_code(icmp_code);
            if let Some(x) = reachable_time {
                icmp_pkt.set_reachable_time(x);
            }

            if let Some(x) = retransmit_time {
                icmp_pkt.set_retrans_time(x);
            }
            if let Some(x) = flags {
                icmp_pkt.set_flags(x);
            }

            icmp_pkt.set_hop_limit(pkt.get_hop_limit());

            if !data.is_empty() {
                safe_copy_from_slice(
                    &mut icmp_buf,
                    icmp_pkt_size,
                    total_length,
                    &data[..],
                    0,
                    data.len(),
                )?;
            }
        }
        Icmpv6Types::NeighborSolicit => {
            let mut icmp_pkt = MutableNeighborSolicitPacket::new(&mut icmp_buf).unwrap();

            icmp_pkt.set_icmpv6_type(icmp_type);
            icmp_pkt.set_icmpv6_code(icmp_code);
            icmp_pkt.set_target_addr(pkt.get_destination());

            if !data.is_empty() {
                safe_copy_from_slice(
                    &mut icmp_buf,
                    icmp_pkt_size,
                    total_length,
                    &data[..],
                    0,
                    data.len(),
                )?;
            }
        }
        Icmpv6Types::NeighborAdvert => {
            let mut icmp_pkt = MutableNeighborAdvertPacket::new(&mut icmp_buf).unwrap();

            icmp_pkt.set_icmpv6_type(icmp_type);
            icmp_pkt.set_icmpv6_code(icmp_code);

            if let Some(x) = flags {
                icmp_pkt.set_flags(x);
                if x & 0b10000000_u8 == 0b10000000 {
                    icmp_pkt.set_target_addr(pkt.get_source());
                } else if let Some(ip_address) = target {
                    icmp_pkt.set_target_addr(ip_address);
                } else {
                    return Err(
                        error(
                            "forge_icmp_v6_package: missing 'target' parameter required for constructing response to a Neighbor Solicitation".to_string()));
                }
            }
        }
        _ => {
            let mut icmp_pkt = packet::icmpv6::MutableIcmpv6Packet::new(&mut icmp_buf).unwrap();

            icmp_pkt.set_icmpv6_type(icmp_type);
            icmp_pkt.set_icmpv6_code(icmp_code);

            if let Some(x) = icmp_id {
                safe_copy_from_slice(&mut icmp_buf, 4, 6, &x.to_le_bytes()[..], 0, 2)?;
            }

            if let Some(x) = icmp_seq {
                safe_copy_from_slice(&mut icmp_buf, 6, 8, &x.to_le_bytes()[..], 0, 2)?;
            }
        }
    }

    if !data.is_empty() {
        safe_copy_from_slice(
            &mut icmp_buf,
            icmp_pkt_size,
            total_length,
            &data[..],
            0,
            data.len(),
        )?;
    }

    let mut icmp_pkt = packet::icmpv6::MutableIcmpv6Packet::new(&mut icmp_buf)
        .ok_or_else(|| error("Not possible to create a icmp packet from buffer".to_string()))?;

    let chksum = match icmp_cksum {
        Some(x) if x != 0 => x.to_be() as u16,
        _ => pnet::packet::icmpv6::checksum(
            &icmp_pkt.to_immutable(),
            &pkt.get_source(),
            &pkt.get_destination(),
        ),
    };
    icmp_pkt.set_checksum(chksum);

    let l = icmp_buf.len();
    let mut icmp_buf_aux = vec![0u8; icmp_buf.len()];
    ip_buf.append(&mut icmp_buf_aux);

    let mut pkt = packet::ipv6::MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
    pkt.set_payload_length(l as u16);
    pkt.set_payload(&icmp_buf);
    if !update_ip_len.unwrap_or(true) {
        pkt.set_payload_length(original_ip_len as u16);
    };

    Ok(NaslValue::Data(ip_buf))
}

enum Icmpv6Element {
    Id,
    Code,
    Type,
    Seq,
    CheckSum,
    Data,
}

impl FromStr for Icmpv6Element {
    type Err = ArgumentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "icmp_id" => Ok(Self::Id),
            "icmp_code" => Ok(Self::Code),
            "icmp_type" => Ok(Self::Type),
            "icmp_seq" => Ok(Self::Seq),
            "icmp_chsum" => Ok(Self::CheckSum),
            "icmp_data" => Ok(Self::Data),
            s => Err(ArgumentError::WrongArgument(format!(
                "Invalid element for ICMP packet: {}",
                s
            ))),
        }
    }
}

impl PacketElement for Icmpv6Element {
    type Packet<'a> = Icmpv6Packet<'a>;

    fn get_element(&self, icmp: &Self::Packet<'_>) -> NaslValue {
        match self {
            Self::Code => NaslValue::Number(icmp.get_icmpv6_code().0 as i64),
            Self::Type => NaslValue::Number(icmp.get_icmpv6_type().0 as i64),
            Self::CheckSum => NaslValue::Number(icmp.get_checksum() as i64),
            Self::Id => {
                if icmp.payload().len() >= 4 {
                    let pl = icmp.payload();
                    let mut id = [0u8; 8];
                    //id[..2].copy_from_slice(&pl[..2]);
                    // It is safe to unwrap, since the destination buffer is known.
                    safe_copy_from_slice(&mut id, 0, 2, pl, 0, 2).unwrap();
                    NaslValue::Number(i64::from_le_bytes(id))
                } else {
                    NaslValue::Number(0)
                }
            }
            Self::Seq => {
                if icmp.payload().len() >= 4 {
                    let pl = icmp.payload();
                    let mut seq = [0u8; 8];
                    //seq[0..2].copy_from_slice(&pl[2..4]);
                    // It is safe to unwrap, since the destination buffer is known.
                    safe_copy_from_slice(&mut seq, 0, 2, pl, 2, 4).unwrap();

                    NaslValue::Number(i64::from_le_bytes(seq))
                } else {
                    NaslValue::Number(0)
                }
            }
            Self::Data => {
                if icmp.payload().len() > 4 {
                    let buf = icmp.payload();
                    NaslValue::Data(buf[4..].to_vec())
                } else {
                    NaslValue::Null
                }
            }
        }
    }
}

impl FromNaslValue<'_> for Icmpv6Element {
    fn from_nasl_value(value: &NaslValue) -> Result<Self, FnError> {
        let s = String::from_nasl_value(value)?;
        Ok(Icmpv6Element::from_str(&s)?)
    }
}

/// Get an ICMPv6 element from a IPv6 packet. It returns a data block or an integer, according to the type of the element. Its arguments are:
/// - icmp: is the IP datagram (not the ICMP part only).
/// - element: is the name of the field to get
///
/// Valid ICMP elements to get are:
/// - icmp_id
/// - icmp_code
/// - icmp_type
/// - icmp_seq
/// - icmp_chsum
/// - icmp_data
#[nasl_function(named(icmp, element))]
fn get_icmp_v6_element(icmp: Icmpv6Packet, element: Icmpv6Element) -> Result<NaslValue, FnError> {
    Ok(element.get_element(&icmp))
}

fn print_icmpv6_packet(icmp: &Icmpv6Packet) {
    println!("------");
    println!("\ticmp6_id    : {:?}", Icmpv6Element::Id.get_element(icmp));
    println!(
        "\ticmp6_code  : {:?}",
        Icmpv6Element::Code.get_element(icmp)
    );
    println!("\ticmp_type  : {:?}", Icmpv6Element::Type.get_element(icmp));
    println!("\ticmp6_seq   : {:?}", Icmpv6Element::Seq.get_element(icmp));
    println!(
        "\ticmp6_cksum : {:?}",
        Icmpv6Element::CheckSum.get_element(icmp)
    );
    println!("\tData       : {:?}", Icmpv6Element::Data.get_element(icmp));
    println!("\n");
}

/// Receive a list of IPv6 ICMP packets and print them in a readable format in the screen.
#[nasl_function]
fn dump_icmp_v6_packet(positional: CheckedPositionals<Icmpv6Packet>) -> Result<NaslValue, FnError> {
    for icmp_pkt in positional.iter() {
        let pkt = Icmpv6Packet::new(icmp_pkt.payload())
            .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;
        print_icmpv6_packet(&pkt);
    }
    Ok(NaslValue::Null)
}

#[nasl_function]
fn forge_igmp_v6_packet() -> Result<NaslValue, FnError> {
    // TODO!: not implemented. Multicast management on IPv6 networks is handled by Multicast
    // Listener Discovery (MLD) which is a part of ICMPv6 in contrast to IGMP's bare IP encapsulation.
    // Currently, pnet does not support MDL.
    Ok(NaslValue::Null)
}

pub fn nasl_tcp_v6_ping_shared(configs: &ScanCtx, port: Option<u16>) -> Result<NaslValue, FnError> {
    let rnd_tcp_port = || -> u16 { (random_impl().unwrap_or(0) % 65535 + 1024) as u16 };

    let sports_ori: Vec<u16> = vec![
        0, 0, 0, 0, 0, 1023, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0, 0, 20, 0, 25, 0, 0, 0,
    ];
    let mut sports: Vec<u16> = vec![];
    let ports = [
        139, 135, 445, 80, 22, 515, 23, 21, 6000, 1025, 25, 111, 1028, 9100, 1029, 79, 497, 548,
        5000, 1917, 53, 161, 9001, 65535, 443, 113, 993, 8080,
    ];

    for p in sports_ori.iter() {
        if *p == 0u16 {
            sports.push(rnd_tcp_port());
        } else {
            sports.push(*p);
        }
    }

    let soc = new_raw_ipv6_socket()?;
    if let Err(e) = soc.set_header_included_v6(true) {
        return Err(error(format!("Not possible to create a raw socket: {}", e)));
    };

    // Get the iface name, to set the capture device.
    let target_ip = configs.target().ip_addr();
    let local_ip = get_source_ip(target_ip)?;
    let iface = get_interface_by_local_ip(local_ip)?;

    let port = port.unwrap_or(configs.get_host_open_port().unwrap_or_default());

    if islocalhost(target_ip) {
        return Ok(NaslValue::Number(1));
    }

    let mut capture_dev = match Capture::from_device(iface) {
        Ok(c) => match c.promisc(true).timeout(100).open() {
            Ok(capture) => capture,
            Err(e) => return custom_error!("send_packet: {}", e),
        },
        Err(e) => return custom_error!("send_packet: {}", e),
    };
    let filter = format!("ip and src host {}", target_ip);

    let mut ip_buf = [0u8; FIX_IPV6_HEADER_LENGTH];
    let mut ip = MutableIpv6Packet::new(&mut ip_buf)
        .ok_or_else(|| error("Not possible to create a packet from buffer".to_string()))?;

    ip.set_flow_label(0);
    ip.set_traffic_class(0);
    ip.set_version(IPPROTO_IPV6);
    ip.set_next_header(IpNextHeaderProtocols::Tcp);
    ip.set_payload_length(MIN_TCP_HEADER_LENGTH as u16);
    let ipv6_src = Ipv6Addr::from_str(&local_ip.to_string())
        .map_err(|_| ArgumentError::WrongArgument("invalid IP".to_string()))?;
    ip.set_source(ipv6_src);

    let ipv6_dst = Ipv6Addr::from_str(&target_ip.to_string())
        .map_err(|_| ArgumentError::WrongArgument("invalid IP".to_string()))?;
    ip.set_destination(ipv6_dst);

    let mut tcp_buf = [0u8; FIX_IPV6_HEADER_LENGTH];
    let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp.set_flags(TH_SYN);
    tcp.set_sequence(random_impl()? as u32);
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(DEFAULT_TCP_DATA_OFFSET_32BIT_INCREMENTS);
    tcp.set_window(2048);
    tcp.set_urgent_ptr(0);

    for (i, _) in sports.iter().enumerate() {
        let mut sport = rnd_tcp_port();
        let mut dport = port;
        if port == 0 {
            sport = sports[i];
            dport = ports[i] as u16;
        }

        tcp.set_source(sport);
        tcp.set_destination(dport);
        let chksum = tcp.calculate_checksum(None, &ip.to_immutable());
        tcp.set_checksum(chksum);
        ip.set_payload(tcp.packet());

        let sockaddr = socket2::SockAddr::from(SocketAddr::new(target_ip, 0));
        match soc.send_to(ip.packet(), &sockaddr) {
            Ok(b) => {
                debug!("Sent {} bytes", b);
            }
            Err(e) => {
                return Err(error(format!("send_packet: {}", e)));
            }
        }

        let p = match capture_dev.filter(&filter, true) {
            Ok(_) => capture_dev.next_packet(),
            Err(e) => Err(pcap::Error::PcapError(e.to_string())),
        };

        if p.is_ok() {
            return Ok(NaslValue::Number(1));
        }
    }
    Ok(NaslValue::Null)
}

/// This function tries to open a TCP connection and sees if anything comes back (SYN/ACK or RST).
///
/// Its argument is:
/// - port: port for the ping
#[nasl_function(named(port))]
pub fn nasl_tcp_v6_ping(configs: &ScanCtx, port: Option<u16>) -> Result<NaslValue, FnError> {
    nasl_tcp_v6_ping_shared(configs, port)
}

/// Send a list of packets, passed as unnamed arguments, with the option to listen to the answers.
///
/// The arguments are:
/// - Any number of packets to send
/// - length: default length of each every packet, if a packet does not fit, its actual size is taken instead
/// - pcap_active: option to capture the answers, TRUE by default
/// - pcap_filter: BPF filter used for the answers
/// - pcap_timeout: time to wait for the answers in seconds, 5 by default
/// - allow_broadcast: default FALSE
#[nasl_function(named(length, pcap_active, pcap_filter, pcap_timeout))]
fn nasl_send_v6packet(
    configs: &ScanCtx,
    length: Option<i32>,
    pcap_active: Option<bool>,
    pcap_filter: Option<String>,
    pcap_timeout: Option<i32>,
    positional: CheckedPositionals<Ipv6Packet>,
) -> Result<NaslValue, FnError> {
    let use_pcap = pcap_active.unwrap_or(true);
    let filter = pcap_filter.unwrap_or_default();
    let timeout = pcap_timeout.unwrap_or(DEFAULT_TIMEOUT) * 1000;

    if positional.is_empty() {
        return Ok(NaslValue::Null);
    }

    let soc = new_raw_ipv6_socket()?;

    if let Err(e) = soc.set_header_included_v6(true) {
        return Err(error(format!(
            "send_v6packet: Not possible to create a raw socket: {}",
            e
        )));
    };

    let _dflt_packet_sz = length.unwrap_or_default();

    // Get the iface name, to set the capture device.
    let target_ip = configs.target().ip_addr();
    let local_ip = get_source_ip(target_ip)?;
    let iface = get_interface_by_local_ip(local_ip)?;

    let mut capture_dev = match Capture::from_device(iface) {
        Ok(c) => match c.promisc(true).timeout(timeout).open() {
            Ok(capture) => capture,
            Err(e) => return custom_error!("send_packet: {}", e),
        },
        Err(e) => return custom_error!("send_packet: {}", e),
    };

    for packet in positional.iter() {
        // If dst ip address inside the IP packet differs from target IP, it is consider a malicious or buggy script.
        if packet.get_destination() != target_ip {
            return Err(error(format!(
                "send_packet: malicious or buggy script is trying to send packet to {} instead of designated target {}",
                packet.get_destination(),
                target_ip
            )));
        }

        let sock_str = format!("[{}]:{}", &packet.get_destination().to_string().as_str(), 0);

        let sockaddr = match SocketAddr::from_str(&sock_str) {
            Ok(addr) => socket2::SockAddr::from(addr),
            Err(e) => {
                return Err(error(format!("send_packet: {}", e)));
            }
        };

        match soc.send_to(packet.packet(), &sockaddr) {
            Ok(b) => {
                debug!("Sent {} bytes", b);
            }
            Err(e) => {
                return Err(error(format!("send_packet: {}", e)));
            }
        }

        if use_pcap {
            let p = match capture_dev.filter(&filter, true) {
                Ok(_) => capture_dev.next_packet(),
                Err(e) => Err(pcap::Error::PcapError(e.to_string())),
            };

            match p {
                Ok(packet) => return Ok(NaslValue::Data(packet.data.to_vec())),
                Err(_) => return Ok(NaslValue::Null),
            };
        }
    }
    Ok(NaslValue::Null)
}

/// Returns a NaslVars with all predefined variables which must be expose to nasl script
pub fn expose_vars() -> NaslVars<'static> {
    let builtin_vars: NaslVars = [
        (
            "IPPROTO_TCP",
            NaslValue::Number(IpNextHeaderProtocols::Tcp.to_primitive_values().0.into()),
        ),
        (
            "IPPROTO_UDP",
            NaslValue::Number(IpNextHeaderProtocols::Udp.to_primitive_values().0.into()),
        ),
        (
            "IPPROTO_ICMP",
            NaslValue::Number(IpNextHeaderProtocols::Icmp.to_primitive_values().0.into()),
        ),
        (
            "IPPROTO_IGMP",
            NaslValue::Number(IpNextHeaderProtocols::Igmp.to_primitive_values().0.into()),
        ),
        ("IPPROTO_IP", NaslValue::Number(IPPROTO_IP.into())),
        ("TH_FIN", NaslValue::Number(TcpFlags::FIN.into())),
        ("TH_SYN", NaslValue::Number(TcpFlags::SYN.into())),
        ("TH_RST", NaslValue::Number(TcpFlags::RST.into())),
        ("TH_PUSH", NaslValue::Number(TcpFlags::PSH.into())),
        ("TH_ACK", NaslValue::Number(TcpFlags::ACK.into())),
        ("TH_URG", NaslValue::Number(TcpFlags::URG.into())),
        ("IP_RF", NaslValue::Number(IP_RF)),
        ("IP_DF", NaslValue::Number(IP_DF)),
        ("IP_MF", NaslValue::Number(IP_MF)),
        ("IP_OFFMASK", NaslValue::Number(IP_OFFMASK)),
        (
            "TCPOPT_MAXSEG",
            NaslValue::Number(TcpOptionNumbers::MSS.to_primitive_values().0 as i64),
        ),
        (
            "TCPOPT_WINDOW",
            NaslValue::Number(TcpOptionNumbers::WSCALE.to_primitive_values().0 as i64),
        ),
        (
            "TCPOPT_SACK_PERMITTED",
            NaslValue::Number(TcpOptionNumbers::SACK_PERMITTED.to_primitive_values().0 as i64),
        ),
        (
            "TCPOPT_TIMESTAMP",
            NaslValue::Number(TcpOptionNumbers::TIMESTAMPS.to_primitive_values().0 as i64),
        ),
    ]
    .iter()
    .cloned()
    .collect();
    builtin_vars
}

pub struct PacketForgery;

function_set! {
    PacketForgery,
    (
        forge_ip_packet,
        set_ip_elements,
        get_ip_element,
        dump_ip_packet,
        insert_ip_options,
        forge_tcp_packet,
        get_tcp_element,
        get_tcp_option,
        set_tcp_elements,
        (insert_tcp_v4_options, "insert_tcp_options"),
        dump_tcp_packet,
        forge_udp_packet,
        set_udp_elements,
        dump_udp_packet,
        get_udp_element,
        forge_icmp_packet,
        get_icmp_element,
        dump_icmp_packet,
        forge_igmp_packet,
        (nasl_tcp_ping, "tcp_ping"),
        (nasl_send_packet, "send_packet"),
        // These two functions are the same
        (nasl_send_capture, "pcap_next"),
        (nasl_send_capture, "send_capture"),

      //IPv6
        forge_ip_v6_packet,
        get_ip_v6_element,
        set_ip_v6_elements,
        insert_ip_v6_options,
        dump_ip_v6_packet,
        forge_tcp_v6_packet,
        (get_tcp_element, "get_tcp_v6_element"),
        (get_tcp_option, "get_tcp_v6_option"),
        set_tcp_v6_elements,
        insert_tcp_v6_options,
        dump_tcp_v6_packet,
        (nasl_tcp_v6_ping, "tcp_v6_ping"),
        forge_udp_v6_packet,
        (get_udp_element, "get_udp_v6_element"),
        set_udp_v6_elements,
        (dump_udp_packet, "dump_udp_v6_packet"),
        forge_icmp_v6_packet,
        get_icmp_v6_element,
        dump_icmp_v6_packet,
        forge_igmp_v6_packet,
        (nasl_send_v6packet, "send_v6packet"),
    )
}
