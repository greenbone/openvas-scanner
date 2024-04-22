// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL packet forgery functions

use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

use super::raw_ip_utils::{get_interface_by_local_ip, get_source_ip, islocalhost};

use nasl_builtin_host::get_host_ip;
use nasl_builtin_misc::random_impl;
use nasl_builtin_utils::{
    Context, ContextType, FunctionErrorKind, NaslFunction, NaslVars, Register,
};
use nasl_syntax::{logger::NaslLogger, NaslValue};

use pcap::Capture;
use pnet::packet::{
    self,
    ethernet::EthernetPacket,
    icmp::*,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{checksum, MutableIpv4Packet},
    tcp::{TcpOption, TcpOptionNumbers, TcpPacket, *},
    udp::UdpPacket,
    Packet, PrimitiveValues,
};

use socket2::{Domain, Protocol, Socket};

macro_rules! custom_error {
    ($a:expr, $b:expr) => {
        Err(FunctionErrorKind::Diagnostic(
            format!($a, $b),
            Some(NaslValue::Null),
        ))
    };
}

/// Default Timeout for received
const DEFAULT_TIMEOUT: i32 = 5000;

/// Define IPPROTO_RAW
const IPPROTO_RAW: i32 = 255;
/// Define IPPROTO_IP for dummy tcp . From rfc3542:
// Berkeley-derived IPv4 implementations also define IPPROTO_IP to be 0.
// This should not be a problem since IPPROTO_IP is used only with IPv4
// sockets and IPPROTO_HOPOPTS only with IPv6 sockets.
const IPPROTO_IP: u8 = 0;
/// Reserved fragment flag
const IP_RF: i64 = 0x8000;
/// Dont fragment flag
const IP_DF: i64 = 0x4000;
/// More fragments flag
const IP_MF: i64 = 0x2000;
/// Mask for fragmenting bits
const IP_OFFMASK: i64 = 0x1fff;

/// print the raw packet
pub fn display_packet(logger: &dyn NaslLogger, vector: &[u8]) {
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
    logger.info(&s);
}

/// Copy from a slice in safe way, performing the necessary test to avoid panicking
fn safe_copy_from_slice(
    d_buf: &mut [u8],
    d_init: usize,
    d_fin: usize,
    o_buf: &[u8],
    o_init: usize,
    o_fin: usize,
) -> Result<(), FunctionErrorKind> {
    let o_range = o_fin - o_init;
    let d_range = d_fin - d_init;
    if d_buf.len() < d_range
        || o_buf.len() < o_range
        || o_range != d_range
        || d_buf.len() < d_fin
        || o_buf.len() < o_fin
    {
        return Err(FunctionErrorKind::Dirty(
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
fn forge_ip_packet<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let dst_addr = get_host_ip(configs)?;

    if dst_addr.is_ipv6() {
        return Err(FunctionErrorKind::WrongArgument(
            "forge_ip_packet: No valid dst_addr could be determined via call to get_host_ip()"
                .to_string(),
        ));
    }

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    let total_length = 20 + data.len();
    let mut buf = vec![0; total_length];
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Diagnostic(
            "No possible to create a packet from buffer".to_string(),
            None,
        )
    })?;

    pkt.set_total_length(total_length as u16);

    if !data.is_empty() {
        pkt.set_payload(&data);
    }

    let ip_hl = match register.named("ip_hl") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 5_u8,
    };
    pkt.set_header_length(ip_hl);

    let ip_v = match register.named("ip_v") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 4_u8,
    };
    pkt.set_version(ip_v);

    let ip_tos = match register.named("ip_tos") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 0_u8,
    };
    pkt.set_dscp(ip_tos);

    let ip_ttl = match register.named("ip_ttl") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 0_u8,
    };
    pkt.set_ttl(ip_ttl);

    let ip_id = match register.named("ip_id") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
        _ => random_impl()? as u16,
    };
    pkt.set_identification(ip_id.to_be());

    let ip_off = match register.named("ip_off") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
        _ => 0_u16,
    };
    pkt.set_fragment_offset(ip_off);

    let ip_p = match register.named("ip_p") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => 0_u8,
    };
    pkt.set_next_level_protocol(IpNextHeaderProtocol::new(ip_p));

    match register.named("ip_src") {
        Some(ContextType::Value(NaslValue::String(x))) => {
            match x.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    pkt.set_source(ip);
                }
                Err(e) => {
                    return Err(FunctionErrorKind::WrongArgument(format!(
                        "Invalid ip_src: {}",
                        e
                    )));
                }
            };
            x.to_string()
        }
        _ => String::new(),
    };

    match register.named("ip_dst") {
        Some(ContextType::Value(NaslValue::String(x))) => {
            match x.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    pkt.set_destination(ip);
                }
                Err(e) => {
                    return Err(FunctionErrorKind::WrongArgument(format!(
                        "Invalid ip_dst: {}",
                        e
                    )));
                }
            };
            x.to_string()
        }
        _ => {
            match dst_addr.to_string().parse::<Ipv4Addr>() {
                Ok(ip) => {
                    pkt.set_destination(ip);
                }
                Err(e) => {
                    return Err(FunctionErrorKind::WrongArgument(format!(
                        "Invalid ip: {}",
                        e
                    )));
                }
            };
            dst_addr.to_string()
        }
    };

    let ip_sum = match register.named("ip_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) => (*x as u16).to_be(),
        _ => checksum(&pkt.to_immutable()),
    };
    pkt.set_checksum(ip_sum);

    Ok(NaslValue::Data(buf))
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
fn set_ip_elements<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let mut buf = match register.named("ip") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            // Missingarguments
            return Err(FunctionErrorKind::from("ip"));
        }
    };

    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Diagnostic(
            "No possible to create a packet from buffer".to_string(),
            None,
        )
    })?;

    let ip_hl = match register.named("ip_hl") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => pkt.get_header_length(),
    };
    pkt.set_header_length(ip_hl);

    let ip_v = match register.named("ip_v") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => pkt.get_version(),
    };
    pkt.set_version(ip_v);

    let ip_tos = match register.named("ip_tos") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => pkt.get_dscp(),
    };
    pkt.set_dscp(ip_tos);

    let ip_ttl = match register.named("ip_ttl") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u8,
        _ => pkt.get_ttl(),
    };
    pkt.set_ttl(ip_ttl);

    let ip_id = match register.named("ip_id") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
        _ => pkt.get_identification(),
    };
    pkt.set_identification(ip_id.to_be());

    let ip_off = match register.named("ip_off") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as u16,
        _ => pkt.get_fragment_offset(),
    };
    pkt.set_fragment_offset(ip_off);

    let ip_p = match register.named("ip_p") {
        Some(ContextType::Value(NaslValue::Number(x))) => IpNextHeaderProtocol(*x as u8),
        _ => pkt.get_next_level_protocol(),
    };
    pkt.set_next_level_protocol(ip_p);

    if let Some(ContextType::Value(NaslValue::String(x))) = register.named("ip_src") {
        match x.parse::<Ipv4Addr>() {
            Ok(ip) => {
                pkt.set_source(ip);
            }
            Err(e) => {
                return Err(FunctionErrorKind::WrongArgument(format!(
                    "Invalid ip_src: {}",
                    e
                )));
            }
        };
    };

    let ip_sum = match register.named("ip_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) => (*x as u16).to_be(),
        _ => pkt.get_checksum(),
    };
    pkt.set_checksum(ip_sum);

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
fn get_ip_element<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("ip") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("ip"));
        }
    };

    let pkt = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    match register.named("element") {
        Some(ContextType::Value(NaslValue::String(e))) => match e.as_str() {
            "ip_v" => Ok(NaslValue::Number(pkt.get_version() as i64)),
            "ip_id" => Ok(NaslValue::Number(pkt.get_identification() as i64)),
            "ip_hl" => Ok(NaslValue::Number(pkt.get_header_length() as i64)),
            "ip_tos" => Ok(NaslValue::Number(pkt.get_dscp() as i64)),
            "ip_len" => Ok(NaslValue::Number(pkt.get_total_length() as i64)),
            "ip_off" => Ok(NaslValue::Number(pkt.get_fragment_offset() as i64)),
            "ip_ttl" => Ok(NaslValue::Number(pkt.get_ttl() as i64)),
            "ip_p" => Ok(NaslValue::Number(pkt.get_next_level_protocol().0 as i64)),
            "ip_sum" => Ok(NaslValue::Number(pkt.get_checksum() as i64)),
            "ip_src" => Ok(NaslValue::String(pkt.get_source().to_string())),
            "ip_dst" => Ok(NaslValue::String(pkt.get_destination().to_string())),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Invalid element".to_string(),
            )),
        },
        // Missingarguments
        _ => Err(FunctionErrorKind::from("element")),
    }
}

/// Receive a list of IP packets and print them in a readable format in the screen.
fn dump_ip_packet<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Err(FunctionErrorKind::MissingPositionalArguments {
            expected: 1,
            got: 0,
        });
    }

    for ip in positional.iter() {
        match ip {
            NaslValue::Data(data) => {
                let pkt = packet::ipv4::Ipv4Packet::new(data).ok_or_else(|| {
                    FunctionErrorKind::Dirty(
                        "No possible to create a packet from buffer".to_string(),
                    )
                })?;
                configs.logger().info(&"------\n");
                configs
                    .logger()
                    .info(&format!("\tip_hl  : {:?}", pkt.get_header_length()));
                configs
                    .logger()
                    .info(&format!("\tip_v   : {:?}", pkt.get_version()));
                configs
                    .logger()
                    .info(&format!("\tip_tos : {:?}", pkt.get_dscp()));
                configs
                    .logger()
                    .info(&format!("\tip_len : {:?}", pkt.get_total_length()));
                configs
                    .logger()
                    .info(&format!("\tip_id  : {:?}", pkt.get_identification()));
                configs
                    .logger()
                    .info(&format!("\tip_off : {:?}", pkt.get_fragment_offset()));
                configs
                    .logger()
                    .info(&format!("\tip_ttl : {:?}", pkt.get_ttl()));

                match pkt.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => configs.logger().info(&format!(
                        "\tip_p   : IPPROTO_TCP ({:?})",
                        pkt.get_next_level_protocol().to_primitive_values().0
                    )),
                    IpNextHeaderProtocols::Udp => configs.logger().info(&format!(
                        "\tip_p   : IPPROTO_UDP ({:?})",
                        pkt.get_next_level_protocol().to_primitive_values().0
                    )),
                    IpNextHeaderProtocols::Icmp => configs.logger().info(&format!(
                        "\tip_p   : IPPROTO_ICMP ({:?})",
                        pkt.get_next_level_protocol().to_primitive_values().0
                    )),
                    _ => configs.logger().info(&format!(
                        "\tip_p   : IPPROTO_ICMP ({:?})",
                        pkt.get_next_level_protocol().to_primitive_values().0
                    )),
                };

                configs
                    .logger()
                    .info(&format!("\tip_sum  : {:?}", pkt.get_checksum()));
                configs
                    .logger()
                    .info(&format!("\tip_src : {:?}", pkt.get_source().to_string()));
                configs.logger().info(&format!(
                    "\tip_dst : {:?}",
                    pkt.get_destination().to_string()
                ));
                display_packet(configs.logger(), data);
            }
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    "Invalid ip packet".to_string(),
                ));
            }
        }
    }

    Ok(NaslValue::Null)
}

/// Add a option to a specified IP datagram.
///  
/// - ip: is the IP datagram
/// - code: is the identifier of the option to add
/// - length: is the length of the option data
/// - value: is the option data
fn insert_ip_options<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("ip") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("ip"));
        }
    };

    let code = match register.named("code") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x,
        _ => {
            return Err(FunctionErrorKind::from("code"));
        }
    };
    let length = match register.named("length") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as usize,
        _ => {
            return Err(FunctionErrorKind::from("length"));
        }
    };
    let value = match register.named("value") {
        Some(ContextType::Value(NaslValue::String(x))) => x.as_bytes(),
        Some(ContextType::Value(NaslValue::Data(x))) => x,
        _ => {
            return Err(FunctionErrorKind::from("value"));
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
    safe_copy_from_slice(&mut opt_buf[..], 3, length, value, 0, value.len())?;

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

    let mut new_pkt = MutableIpv4Packet::new(&mut new_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let checksum = checksum(&new_pkt.to_immutable());
    new_pkt.set_checksum(checksum);
    new_pkt.set_header_length((hl / 4) as u8);
    Ok(NaslValue::Data(new_pkt.packet().to_vec()))
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
fn forge_tcp_packet<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let mut ip_buf = match register.named("ip") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            // Missingarguments
            return Err(FunctionErrorKind::from("ip"));
        }
    };
    let original_ip_len = ip_buf.len();

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    //tcp length + data length
    let total_length = 20 + data.len();
    let mut buf = vec![0; total_length];
    let mut tcp_seg = packet::tcp::MutableTcpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    if !data.is_empty() {
        tcp_seg.set_payload(&data);
    }

    match register.named("th_sport") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_source(*x as u16),
        _ => tcp_seg.set_source(0_u16),
    };
    match register.named("th_dport") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_destination(*x as u16),
        _ => tcp_seg.set_destination(0_u16),
    };

    match register.named("th_seq") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_sequence(*x as u32),
        _ => tcp_seg.set_sequence(random_impl()? as u32),
    };
    match register.named("th_ack") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_acknowledgement(*x as u32),
        _ => tcp_seg.set_acknowledgement(0_u32),
    };
    match register.named("th_x2") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_reserved(*x as u8),
        _ => tcp_seg.set_reserved(0_u8),
    };
    match register.named("th_off") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_data_offset(*x as u8),
        _ => tcp_seg.set_data_offset(5_u8),
    };
    match register.named("th_flags") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_flags(*x as u16),
        _ => tcp_seg.set_flags(0_u16),
    };
    match register.named("th_win") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_window(*x as u16),
        _ => tcp_seg.set_window(0_u16),
    };
    match register.named("th_urp") {
        Some(ContextType::Value(NaslValue::Number(x))) => tcp_seg.set_urgent_ptr(*x as u16),
        _ => tcp_seg.set_urgent_ptr(0_u16),
    };

    let chksum = match register.named("th_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) if *x != 0 => (*x as u16).to_be(),
        _ => {
            let pkt = packet::ipv4::Ipv4Packet::new(&ip_buf).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            let tcp_aux = TcpPacket::new(tcp_seg.packet()).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            pnet::packet::tcp::ipv4_checksum(&tcp_aux, &pkt.get_source(), &pkt.get_destination())
        }
    };

    let mut tcp_seg = packet::tcp::MutableTcpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    tcp_seg.set_checksum(chksum);

    ip_buf.append(&mut buf);
    let l = ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    pkt.set_total_length(l as u16);
    match register.named("update_ip_len") {
        Some(ContextType::Value(NaslValue::Boolean(l))) if !(*l) => {
            pkt.set_total_length(original_ip_len as u16);
        }
        _ => (),
    };
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
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
fn get_tcp_element<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("tcp") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("tcp"));
        }
    };

    let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let tcp = packet::tcp::TcpPacket::new(ip.payload()).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    match register.named("element") {
        Some(ContextType::Value(NaslValue::String(el))) => match el.as_str() {
            "th_sport" => Ok(NaslValue::Number(tcp.get_source() as i64)),
            "th_dport" => Ok(NaslValue::Number(tcp.get_destination() as i64)),
            "th_seq" => Ok(NaslValue::Number(tcp.get_sequence() as i64)),
            "th_ack" => Ok(NaslValue::Number(tcp.get_acknowledgement() as i64)),
            "th_x2" => Ok(NaslValue::Number(tcp.get_reserved() as i64)),
            "th_off" => Ok(NaslValue::Number(tcp.get_data_offset() as i64)),
            "th_flags" => Ok(NaslValue::Number(tcp.get_flags() as i64)),
            "th_win" => Ok(NaslValue::Number(tcp.get_window() as i64)),
            "th_sum" => Ok(NaslValue::Number(tcp.get_checksum() as i64)),
            "th_urp" => Ok(NaslValue::Number(tcp.get_urgent_ptr() as i64)),
            "th_data" => Ok(NaslValue::Data(tcp.payload().to_vec())),
            _ => Err(FunctionErrorKind::WrongArgument("element".to_string())),
        },
        _ => Err(FunctionErrorKind::from("element")),
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
fn get_tcp_option<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("tcp") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("tcp"));
        }
    };

    let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let tcp = packet::tcp::TcpPacket::new(ip.payload()).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

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

    match register.named("option") {
        Some(ContextType::Value(NaslValue::Number(el))) => match el {
            2 => Ok(NaslValue::Number(max_seg)),
            3 => Ok(NaslValue::Number(window)),
            4 => Ok(NaslValue::Number(sack_permitted)),
            8 => Ok(NaslValue::Array(timestamps)),
            _ => Err(FunctionErrorKind::WrongArgument(
                "Invalid option".to_string(),
            )),
        },
        _ => Err(FunctionErrorKind::from("option")),
    }
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
fn set_tcp_elements<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("tcp") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("tcp"));
        }
    };

    let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let iph_len = ip.get_header_length() as usize * 4; // the header length is given in 32-bits words

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    let ori_tcp_buf = <&[u8]>::clone(&ip.payload()).to_owned();
    let mut ori_tcp: packet::tcp::MutableTcpPacket;

    let mut new_buf: Vec<u8>;
    let tcp_total_length: usize;
    if !data.is_empty() {
        //Prepare a new buffer with new size, copy the tcp header and set the new data
        tcp_total_length = 20 + data.len();
        new_buf = vec![0u8; tcp_total_length];
        //new_buf[..20].copy_from_slice(&ori_tcp_buf[..20]);
        safe_copy_from_slice(&mut new_buf[..], 0, 20, &ori_tcp_buf, 0, 20)?;
        ori_tcp = packet::tcp::MutableTcpPacket::new(&mut new_buf).ok_or_else(|| {
            FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
        })?;
        ori_tcp.set_payload(&data);
    } else {
        // Copy the original tcp buffer into the new buffer
        tcp_total_length = ip.payload().len();
        new_buf = vec![0u8; tcp_total_length];
        //new_buf[..].copy_from_slice(&ori_tcp_buf);
        safe_copy_from_slice(
            &mut new_buf[..],
            0,
            tcp_total_length,
            &ori_tcp_buf,
            0,
            ori_tcp_buf.len(),
        )?;
        ori_tcp = packet::tcp::MutableTcpPacket::new(&mut new_buf).ok_or_else(|| {
            FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
        })?;
    }

    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_sport") {
        ori_tcp.set_source(*x as u16);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_dport") {
        ori_tcp.set_destination(*x as u16);
    };

    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_seq") {
        ori_tcp.set_sequence(*x as u32);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_ack") {
        ori_tcp.set_acknowledgement(*x as u32);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_x2") {
        ori_tcp.set_reserved(*x as u8);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_off") {
        ori_tcp.set_data_offset(*x as u8);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_flags") {
        ori_tcp.set_flags(*x as u16);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_win") {
        ori_tcp.set_window(*x as u16);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("th_urp") {
        ori_tcp.set_urgent_ptr(*x as u16);
    };

    // Set the checksum for the tcp segment
    let chksum = match register.named("th_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) if *x != 0 => (*x as u16).to_be(),
        _ => {
            let pkt = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            let tcp_aux = TcpPacket::new(ori_tcp.packet()).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            pnet::packet::tcp::ipv4_checksum(&tcp_aux, &pkt.get_source(), &pkt.get_destination())
        }
    };
    ori_tcp.set_checksum(chksum);

    // Create a owned copy of the final tcp segment, which will be appended as payload to the IP packet.
    let mut fin_tcp_buf: Vec<u8> = vec![0u8; tcp_total_length];
    let buf_aux = <&[u8]>::clone(&ori_tcp.packet()).to_owned();
    fin_tcp_buf.clone_from_slice(&buf_aux);

    // Create a new IP packet with the original IP header, and the new TCP payload
    let mut new_ip_buf = vec![0u8; iph_len];
    //new_ip_buf[..].copy_from_slice(&buf[..iph_len]);
    safe_copy_from_slice(&mut new_ip_buf[..], 0, iph_len, &buf, 0, iph_len)?;

    new_ip_buf.append(&mut fin_tcp_buf.to_vec());

    let l = new_ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut new_ip_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    // pnet will panic if the total length set in the ip datagram field does not much with the total length.
    // Therefore, the total length is set to the right one before setting the payload.
    // By default it was always updated, but if desired, the original length is set again after setting the payload.
    let original_ip_len = pkt.get_total_length();
    pkt.set_total_length(l as u16);
    pkt.set_payload(&fin_tcp_buf);
    match register.named("update_ip_len") {
        Some(ContextType::Value(NaslValue::Boolean(l))) if !(*l) => {
            pkt.set_total_length(original_ip_len);
        }
        _ => (),
    };

    // New IP checksum
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

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
fn insert_tcp_options<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("tcp") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::Dirty(
                "insert_tcp_options: missing <tcp> field".to_string(),
            ));
        }
    };

    let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let iph_len = ip.get_header_length() as usize * 4; // the header length is given in 32-bits words
    let ori_tcp_buf = <&[u8]>::clone(&ip.payload()).to_owned();
    let mut ori_tcp: packet::tcp::MutableTcpPacket;

    // Get the new data or use the existing one.
    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => {
            let tcp = TcpPacket::new(&ori_tcp_buf).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            tcp.payload().to_vec()
        }
    };

    // Forge the options field
    let positional = register.positional();
    if positional.is_empty() {
        return Err(FunctionErrorKind::Dirty(
            "Missing optional arguments. At least one optional porsitional argument followed by its value must be given".to_string()
        ));
    }

    let mut opts: Vec<TcpOption> = vec![];
    let mut opts_len = 0;
    let mut opts_iter = positional.iter();
    loop {
        match opts_iter.next() {
            Some(NaslValue::Number(o)) if *o == 2 => {
                if let Some(NaslValue::Number(val)) = opts_iter.next() {
                    let v = *val as u16;
                    opts.push(TcpOption::mss(v));
                    opts_len += 4;
                } else {
                    return Err(FunctionErrorKind::WrongArgument(
                        "Invalid value for tcp option TCPOPT_MAXSEG".to_string(),
                    ));
                }
            }
            Some(NaslValue::Number(o)) if *o == 3 => {
                if let Some(NaslValue::Number(val)) = opts_iter.next() {
                    let v = *val as u8;
                    opts.push(TcpOption::wscale(v));
                    opts_len += 3;
                } else {
                    return Err(FunctionErrorKind::WrongArgument(
                        "Invalid value for tcp option TCPOPT_WINDOW".to_string(),
                    ));
                }
            }

            Some(NaslValue::Number(o)) if *o == 4 => {
                opts.push(TcpOption::sack_perm());
                opts_len += 2;
            }
            Some(NaslValue::Number(o)) if *o == 8 => {
                if let Some(NaslValue::Number(val1)) = opts_iter.next() {
                    if let Some(NaslValue::Number(val2)) = opts_iter.next() {
                        let v1 = *val1 as u32;
                        let v2 = *val2 as u32;
                        opts.push(TcpOption::timestamp(v1, v2));
                        opts_len += 10;
                    } else {
                        return Err(FunctionErrorKind::WrongArgument(
                            "Invalid value for tcp option TCPOPT_TIMESTAMP".to_string(),
                        ));
                    }
                } else {
                    return Err(FunctionErrorKind::WrongArgument(
                        "Invalid value for tcp option TCPOPT_TIMESTAMP".to_string(),
                    ));
                }
            }
            None => break,
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    "insert_tcp_options: invalid tcp option".to_string(),
                ));
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

    let mut new_buf: Vec<u8>;
    //Prepare a new buffer with new size, copy the tcp header and set the new data
    let tcp_total_length = 20 + opts_len + data.len();
    new_buf = vec![0u8; tcp_total_length];
    //new_buf[..20].copy_from_slice(&ori_tcp_buf[..20]);
    safe_copy_from_slice(&mut new_buf[..], 0, 20, &ori_tcp_buf, 0, 20)?;

    ori_tcp = packet::tcp::MutableTcpPacket::new(&mut new_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    // At this point, opts len is a 4bytes multiple and the ofset is expressed in 32bits words
    ori_tcp.set_data_offset(5 + opts_len as u8 / 4);
    if !opts.is_empty() {
        ori_tcp.set_options(&opts);
    }
    if !data.is_empty() {
        ori_tcp.set_payload(&data);
    }

    // Set the checksum for the tcp segment
    let chksum = match register.named("th_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) if *x != 0 => (*x as u16).to_be(),
        _ => {
            let pkt = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            let tcp_aux = TcpPacket::new(ori_tcp.packet()).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            pnet::packet::tcp::ipv4_checksum(&tcp_aux, &pkt.get_source(), &pkt.get_destination())
        }
    };
    ori_tcp.set_checksum(chksum);

    // Create a owned copy of the final tcp segment, which will be appended as payload to the IP packet.
    let mut fin_tcp_buf: Vec<u8> = vec![0u8; tcp_total_length];
    let buf_aux = <&[u8]>::clone(&ori_tcp.packet()).to_owned();
    fin_tcp_buf.clone_from_slice(&buf_aux);

    // Create a new IP packet with the original IP header, and the new TCP payload
    let mut new_ip_buf = vec![0u8; iph_len];
    //new_ip_buf[..].copy_from_slice(&buf[..iph_len]);
    safe_copy_from_slice(&mut new_ip_buf[..], 0, iph_len, &buf, 0, iph_len)?;
    new_ip_buf.append(&mut fin_tcp_buf.to_vec());

    let l = new_ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut new_ip_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    // pnet will panic if the total length set in the ip datagram field does not much with the total length.
    // Therefore, the total length is set to the right one before setting the payload.
    // By default it was always updated, but if desired, the original length is set again after setting the payload.
    let original_ip_len = pkt.get_total_length();
    pkt.set_total_length(l as u16);
    pkt.set_payload(&fin_tcp_buf);
    match register.named("update_ip_len") {
        Some(ContextType::Value(NaslValue::Boolean(l))) if !(*l) => {
            pkt.set_total_length(original_ip_len);
        }
        _ => (),
    };

    // New IP checksum
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

/// Receive a list of IPv4 datagrams and print their TCP part in a readable format in the screen.
fn dump_tcp_packet<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Err(FunctionErrorKind::Dirty(
            "Missing arguments. It needs at least one tcp packet".to_string(),
        ));
    }

    for tcp_seg in positional.iter() {
        match tcp_seg {
            NaslValue::Data(data) => {
                let ip = match packet::ipv4::Ipv4Packet::new(data) {
                    Some(ip) => ip,
                    None => {
                        return Err(FunctionErrorKind::WrongArgument(
                            "Invalid TCP packet".to_string(),
                        ));
                    }
                };

                match packet::tcp::TcpPacket::new(ip.payload()) {
                    Some(pkt) => {
                        configs.logger().info(&"------\n");
                        configs
                            .logger()
                            .info(&format!("\tth_sport  : {:?}", pkt.get_source()));
                        configs
                            .logger()
                            .info(&format!("\tth_dport   : {:?}", pkt.get_destination()));
                        configs
                            .logger()
                            .info(&format!("\tth_seq : {:?}", pkt.get_sequence()));
                        configs
                            .logger()
                            .info(&format!("\tth_ack : {:?}", pkt.get_acknowledgement()));
                        configs
                            .logger()
                            .info(&format!("\tth_x2  : {:?}", pkt.get_reserved()));
                        configs
                            .logger()
                            .info(&format!("\tth_off : {:?}", pkt.get_data_offset()));

                        let flags = pkt.get_flags();
                        let mut f = String::new();
                        f.push_str("\tth_flags : ");
                        if flags & pnet::packet::tcp::TcpFlags::FIN
                            == pnet::packet::tcp::TcpFlags::FIN
                        {
                            f.push_str("TH_FIN");
                        }
                        if flags & pnet::packet::tcp::TcpFlags::SYN
                            == pnet::packet::tcp::TcpFlags::SYN
                        {
                            if !f.is_empty() {
                                f.push('|')
                            };
                            f.push_str("TH_SYN");
                        }
                        if flags & pnet::packet::tcp::TcpFlags::RST
                            == pnet::packet::tcp::TcpFlags::RST
                        {
                            if !f.is_empty() {
                                f.push('|')
                            };
                            f.push_str("TH_RST");
                        }
                        if flags & pnet::packet::tcp::TcpFlags::PSH
                            == pnet::packet::tcp::TcpFlags::PSH
                        {
                            if !f.is_empty() {
                                f.push('|')
                            };
                            f.push_str("TH_PSH");
                        }
                        if flags & pnet::packet::tcp::TcpFlags::ACK
                            == pnet::packet::tcp::TcpFlags::ACK
                        {
                            if !f.is_empty() {
                                f.push('|')
                            };
                            f.push_str("TH_ACK");
                        }
                        if flags & pnet::packet::tcp::TcpFlags::URG
                            == pnet::packet::tcp::TcpFlags::URG
                        {
                            if !f.is_empty() {
                                f.push('|')
                            };
                            f.push_str("TH_URG");
                        }
                        if f.is_empty() {
                            f.push_str(" 0");
                        } else {
                            f.push_str(&format!(" {:?}", flags));
                        };
                        configs.logger().info(&f);
                        configs
                            .logger()
                            .info(&format!("\tth_win  : {:?}", pkt.get_window()));
                        configs
                            .logger()
                            .info(&format!("\tth_sum : {:?}", pkt.get_checksum()));
                        configs
                            .logger()
                            .info(&format!("\tth_urp : {:?}", pkt.get_urgent_ptr()));
                        println!("\tTCP Options:");
                        for o in pkt.get_options_iter() {
                            let n = o.get_number();
                            let p = o.payload();
                            if n == TcpOptionNumbers::MSS {
                                configs
                                    .logger()
                                    .info(&format!("\t\tTCPOPT_MAXSEG: {:?}", p));
                            }
                            if n == TcpOptionNumbers::WSCALE {
                                configs
                                    .logger()
                                    .info(&format!("\t\tTCPOPT_WINDOW: {:?}", p));
                            }

                            if n == TcpOptionNumbers::SACK_PERMITTED {
                                configs
                                    .logger()
                                    .info(&format!("\t\tTCPOPT_SACK_PERMITTED: {:?}", p));
                            }
                            if n == TcpOptionNumbers::TIMESTAMPS {
                                configs
                                    .logger()
                                    .info(&format!("\t\tTCPOPT_TIMESTAMP TSval: {:?}", p));
                            }
                        }
                        display_packet(configs.logger(), data);
                    }
                    None => {
                        return Err(FunctionErrorKind::WrongArgument(
                            "Invalid TPC packet".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    "Invalid ip packet".to_string(),
                ));
            }
        }
    }

    Ok(NaslValue::Null)
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
fn forge_udp_packet<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let mut ip_buf = match register.named("ip") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => return Err(FunctionErrorKind::from("ip")),
    };
    let original_ip_len = ip_buf.len();

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    //udp length + data length
    let total_length = 8 + data.len();
    let mut buf = vec![0; total_length];
    let mut udp_datagram = packet::udp::MutableUdpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    if !data.is_empty() {
        udp_datagram.set_payload(&data);
    }

    match register.named("uh_sport") {
        Some(ContextType::Value(NaslValue::Number(x))) => udp_datagram.set_source(*x as u16),
        _ => udp_datagram.set_source(0_u16),
    };
    match register.named("uh_dport") {
        Some(ContextType::Value(NaslValue::Number(x))) => udp_datagram.set_destination(*x as u16),
        _ => udp_datagram.set_destination(0_u16),
    };

    match register.named("uh_len") {
        Some(ContextType::Value(NaslValue::Number(x))) => udp_datagram.set_length(*x as u16),
        _ => udp_datagram.set_length(8u16),
    };

    let chksum = match register.named("th_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) if *x != 0 => (*x as u16).to_be(),
        _ => {
            let pkt = packet::ipv4::Ipv4Packet::new(&ip_buf).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            let udp_aux = UdpPacket::new(udp_datagram.packet()).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            pnet::packet::udp::ipv4_checksum(&udp_aux, &pkt.get_source(), &pkt.get_destination())
        }
    };

    let mut udp_datagram = packet::udp::MutableUdpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    udp_datagram.set_checksum(chksum);

    ip_buf.append(&mut buf);
    let l = ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    pkt.set_total_length(l as u16);
    match register.named("update_ip_len") {
        Some(ContextType::Value(NaslValue::Boolean(l))) if !(*l) => {
            pkt.set_total_length(original_ip_len as u16);
        }
        _ => (),
    };
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
}

/// This function modifies the UDP fields of an IP datagram. Its arguments are:
///  
/// - udp: is the IP datagram to be filled.
/// - data: is the payload.
/// - uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
/// - uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
/// - uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
fn set_udp_elements<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("udp") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("udp"));
        }
    };

    let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let iph_len = ip.get_header_length() as usize * 4; // the header length is given in 32-bits words

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    let ori_udp_buf = <&[u8]>::clone(&ip.payload()).to_owned();
    let mut ori_udp: packet::udp::MutableUdpPacket;

    let mut new_buf: Vec<u8>;
    let udp_total_length: usize;
    if !data.is_empty() {
        //Prepare a new buffer with new size, copy the udp header and set the new data
        udp_total_length = 8 + data.len();
        new_buf = vec![0u8; udp_total_length];
        //new_buf[..8].copy_from_slice(&ori_udp_buf[..8]);
        safe_copy_from_slice(&mut new_buf[..], 0, 8, &ori_udp_buf, 0, 8)?;

        ori_udp = packet::udp::MutableUdpPacket::new(&mut new_buf).ok_or_else(|| {
            FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
        })?;
        ori_udp.set_payload(&data);
    } else {
        // Copy the original udp buffer into the new buffer
        udp_total_length = ip.payload().len();
        new_buf = vec![0u8; udp_total_length];
        //new_buf[..].copy_from_slice(&ori_udp_buf);
        safe_copy_from_slice(
            &mut new_buf[..],
            0,
            udp_total_length,
            &ori_udp_buf,
            0,
            ori_udp_buf.len(),
        )?;
        ori_udp = packet::udp::MutableUdpPacket::new(&mut new_buf).ok_or_else(|| {
            FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
        })?;
    }

    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("uh_sport") {
        ori_udp.set_source(*x as u16);
    };
    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("uh_dport") {
        ori_udp.set_destination(*x as u16);
    };

    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("uh_len") {
        ori_udp.set_length(*x as u16);
    };

    // Set the checksum for the udp segment
    let chksum = match register.named("uh_sum") {
        Some(ContextType::Value(NaslValue::Number(x))) if *x != 0 => (*x as u16).to_be(),
        _ => {
            let pkt = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            let udp_aux = UdpPacket::new(ori_udp.packet()).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            pnet::packet::udp::ipv4_checksum(&udp_aux, &pkt.get_source(), &pkt.get_destination())
        }
    };
    ori_udp.set_checksum(chksum);

    // Create a owned copy of the final udp segment, which will be appended as payload to the IP packet.
    let mut fin_udp_buf: Vec<u8> = vec![0u8; udp_total_length];
    let buf_aux = <&[u8]>::clone(&ori_udp.packet()).to_owned();
    fin_udp_buf.clone_from_slice(&buf_aux);

    // Create a new IP packet with the original IP header, and the new UDP payload
    let mut new_ip_buf = vec![0u8; iph_len];
    //new_ip_buf[..].copy_from_slice(&buf[..iph_len]);
    safe_copy_from_slice(&mut new_ip_buf[..], 0, iph_len, &buf, 0, iph_len)?;
    new_ip_buf.append(&mut fin_udp_buf.to_vec());

    let l = new_ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut new_ip_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    pkt.set_total_length(l as u16);
    pkt.set_payload(&fin_udp_buf);

    // New IP checksum
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(pkt.packet().to_vec()))
}

/// Receive a list of IPv4 datagrams and print their UDP part in a readable format in the screen.
fn dump_udp_packet<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Err(FunctionErrorKind::Dirty(
            "Missing arguments. It needs at least one UDP packet".to_string(),
        ));
    }

    for udp_datagram in positional.iter() {
        match udp_datagram {
            NaslValue::Data(data) => {
                let ip = match packet::ipv4::Ipv4Packet::new(data) {
                    Some(ip) => ip,
                    None => {
                        return Err(FunctionErrorKind::WrongArgument(
                            "Invalid UDP packet".to_string(),
                        ));
                    }
                };

                match packet::udp::UdpPacket::new(ip.payload()) {
                    Some(pkt) => {
                        configs.logger().info(&"------\n");
                        configs
                            .logger()
                            .info(&format!("\tuh_sport  : {:?}", pkt.get_source()));
                        configs
                            .logger()
                            .info(&format!("\tuh_dport   : {:?}", pkt.get_destination()));
                        configs
                            .logger()
                            .info(&format!("\tuh_len : {:?}", pkt.get_length()));
                        configs
                            .logger()
                            .info(&format!("\tuh_sum : {:?}", pkt.get_checksum()));
                        display_packet(configs.logger(), data);
                    }
                    None => {
                        return Err(FunctionErrorKind::WrongArgument(
                            "Invalid UDP packet".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(FunctionErrorKind::WrongArgument(
                    "Invalid UDP packet".to_string(),
                ));
            }
        }
    }

    Ok(NaslValue::Null)
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
fn get_udp_element<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("udp") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("udp"));
        }
    };

    let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let udp = packet::udp::UdpPacket::new(ip.payload()).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    match register.named("element") {
        Some(ContextType::Value(NaslValue::String(el))) => match el.as_str() {
            "uh_sport" => Ok(NaslValue::Number(udp.get_source() as i64)),
            "uh_dport" => Ok(NaslValue::Number(udp.get_destination() as i64)),
            "uh_len" => Ok(NaslValue::Number(udp.get_length() as i64)),
            "uh_sum" => Ok(NaslValue::Number(udp.get_checksum() as i64)),
            "data" => Ok(NaslValue::Data(udp.payload().to_vec())),
            _ => Err(FunctionErrorKind::WrongArgument("element".to_string())),
        },
        _ => Err(FunctionErrorKind::WrongArgument("element".to_string())),
    }
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
fn forge_icmp_packet<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let mut ip_buf = match register.named("ip") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("icmp"));
        }
    };
    let original_ip_len = ip_buf.len();

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    let total_length = 8 + data.len();
    let mut buf = vec![0; total_length];
    let mut icmp_pkt = packet::icmp::MutableIcmpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    match register.named("icmp_type") {
        Some(ContextType::Value(NaslValue::Number(x))) => {
            icmp_pkt.set_icmp_type(packet::icmp::IcmpType::new(*x as u8))
        }
        _ => icmp_pkt.set_icmp_type(packet::icmp::IcmpTypes::EchoReply),
    };

    match register.named("icmp_code") {
        Some(ContextType::Value(NaslValue::Number(x))) => {
            icmp_pkt.set_icmp_code(packet::icmp::IcmpCode::new(*x as u8))
        }
        _ => icmp_pkt.set_icmp_code(packet::icmp::IcmpCode::new(0u8)),
    };

    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("icmp_id") {
        //buf[4..6].copy_from_slice(&x.to_le_bytes()[0..2]);
        safe_copy_from_slice(&mut buf, 4, 6, &x.to_le_bytes()[..], 0, 2)?;
    }

    if let Some(ContextType::Value(NaslValue::Number(x))) = register.named("icmp_seq") {
        //buf[6..8].copy_from_slice(&x.to_le_bytes()[0..2]);
        safe_copy_from_slice(&mut buf, 6, 8, &x.to_le_bytes()[..], 0, 2)?;
    }

    if !data.is_empty() {
        //buf[8..].copy_from_slice(&data[0..]);
        safe_copy_from_slice(&mut buf, 8, total_length, &data[..], 0, data.len())?;
    }

    let chksum = match register.named("icmp_cksum") {
        Some(ContextType::Value(NaslValue::Number(x))) if *x != 0 => (*x as u16).to_be(),
        _ => {
            let icmp_aux = IcmpPacket::new(&buf).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            pnet::packet::icmp::checksum(&icmp_aux)
        }
    };

    let mut icmp_pkt = packet::icmp::MutableIcmpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    icmp_pkt.set_checksum(chksum);

    ip_buf.append(&mut buf);
    let l = ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    pkt.set_total_length(l as u16);
    match register.named("update_ip_len") {
        Some(ContextType::Value(NaslValue::Boolean(l))) if !(*l) => {
            pkt.set_total_length(original_ip_len as u16);
        }
        _ => (),
    };
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
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
fn get_icmp_element<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let buf = match register.named("icmp") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("icmp"));
        }
    };

    let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let icmp = packet::icmp::IcmpPacket::new(ip.payload()).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    match register.named("element") {
        Some(ContextType::Value(NaslValue::String(el))) => match el.as_str() {
            "icmp_code" => Ok(NaslValue::Number(icmp.get_icmp_code().0 as i64)),
            "icmp_type" => Ok(NaslValue::Number(icmp.get_icmp_type().0 as i64)),
            "icmp_cksum" => Ok(NaslValue::Number(icmp.get_checksum() as i64)),
            "icmp_id" => {
                if icmp.payload().len() >= 4 {
                    let pl = icmp.payload();
                    let mut id = [0u8; 8];
                    //id[..2].copy_from_slice(&pl[..2]);
                    safe_copy_from_slice(&mut id, 0, 2, pl, 0, 2)?;
                    Ok(NaslValue::Number(i64::from_le_bytes(id)))
                } else {
                    Ok(NaslValue::Number(0))
                }
            }
            "icmp_seq" => {
                if icmp.payload().len() >= 4 {
                    let pl = icmp.payload();
                    let mut seq = [0u8; 8];
                    //seq[0..2].copy_from_slice(&pl[2..4]);
                    safe_copy_from_slice(&mut seq, 0, 2, pl, 2, 4)?;

                    Ok(NaslValue::Number(i64::from_le_bytes(seq)))
                } else {
                    Ok(NaslValue::Number(0))
                }
            }
            "data" => {
                if icmp.payload().len() > 4 {
                    let buf = icmp.payload();
                    Ok(NaslValue::Data(buf[4..].to_vec()))
                } else {
                    Ok(NaslValue::Null)
                }
            }
            _ => Ok(NaslValue::Null),
        },
        _ => Err(FunctionErrorKind::from("element")),
    }
}

/// Receive a list of IPv4 ICMP packets and print them in a readable format in the screen.
fn dump_icmp_packet<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Err(FunctionErrorKind::from("icmp"));
    }

    for icmp_pkt in positional.iter() {
        let buf = match icmp_pkt {
            NaslValue::Data(d) => d.clone(),
            _ => {
                continue;
            }
        };

        let ip = packet::ipv4::Ipv4Packet::new(&buf).ok_or_else(|| {
            FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
        })?;
        let icmp = packet::icmp::IcmpPacket::new(ip.payload()).ok_or_else(|| {
            FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
        })?;

        let mut icmp_seq = 0;
        if icmp.payload().len() >= 4 {
            let pl = icmp.payload();
            let mut seq = [0u8; 8];
            //seq[0..2].copy_from_slice(&pl[2..4]);
            safe_copy_from_slice(&mut seq, 0, 2, pl, 2, 4)?;
            icmp_seq = i64::from_le_bytes(seq);
        }

        let mut icmp_id = 0;
        if icmp.payload().len() >= 4 {
            let pl = icmp.payload();
            let mut id = [0u8; 8];
            //id[..2].copy_from_slice(&pl[..2]);
            safe_copy_from_slice(&mut id, 0, 2, pl, 0, 2)?;
            icmp_id = i64::from_le_bytes(id);
        }

        let mut data = vec![];
        if icmp.payload().len() > 4 {
            let buf = icmp.payload();
            data = buf[4..].to_vec();
        }

        configs.logger().info(&"------");
        configs
            .logger()
            .info(&format!("\ticmp_id    : {:?}", icmp_id));
        configs
            .logger()
            .info(&format!("\ticmp_code  : {:?}", icmp.get_icmp_code()));
        configs
            .logger()
            .info(&format!("\ticmp_type  : {:?}", icmp.get_icmp_type()));
        configs
            .logger()
            .info(&format!("\ticmp_seq   : {:?}", icmp_seq));
        configs
            .logger()
            .info(&format!("\ticmp_cksum : {:?}", icmp.get_checksum()));
        configs.logger().info(&format!("\tData       : {:?}", data));
        configs.logger().info(&"\n");
    }
    Ok(NaslValue::Null)
}

// IGMP
pub mod igmp {
    use std::net::Ipv4Addr;

    use pnet::packet::{Packet, PrimitiveValues};
    use pnet_macros::packet;
    use pnet_macros_support::types::*;

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
    #[packet]
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
fn forge_igmp_packet<K>(
    register: &Register,
    _configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let mut ip_buf = match register.named("ip") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        _ => {
            return Err(FunctionErrorKind::from("igmp"));
        }
    };
    let original_ip_len = ip_buf.len();

    let data = match register.named("data") {
        Some(ContextType::Value(NaslValue::Data(d))) => d.clone(),
        Some(ContextType::Value(NaslValue::String(d))) => d.as_bytes().to_vec(),
        Some(ContextType::Value(NaslValue::Number(d))) => d.to_be_bytes().to_vec(),
        _ => Vec::<u8>::new(),
    };

    let total_length = 8 + data.len();
    let mut buf = vec![0; total_length];
    let mut igmp_pkt = igmp::MutableIgmpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;

    match register.named("type") {
        Some(ContextType::Value(NaslValue::Number(x))) => {
            igmp_pkt.set_igmp_type(igmp::IgmpType::new(*x as u8))
        }
        _ => igmp_pkt.set_igmp_type(igmp::IgmpTypes::Default),
    };

    match register.named("code") {
        Some(ContextType::Value(NaslValue::Number(x))) => {
            igmp_pkt.set_igmp_timeout((*x as u8).to_be())
        }
        _ => igmp_pkt.set_igmp_timeout(0u8),
    };
    match register.named("group") {
        Some(ContextType::Value(NaslValue::String(x))) => {
            match x.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    igmp_pkt.set_group_address(ip);
                }
                Err(e) => {
                    return Err(FunctionErrorKind::Dirty(format!(
                        "Invalid address group: {}",
                        e
                    )));
                }
            };
        }
        _ => igmp_pkt.set_group_address(Ipv4Addr::new(0, 0, 0, 0)),
    };

    if !data.is_empty() {
        igmp_pkt.set_payload(&data);
    }

    let igmp_aux = igmp::IgmpPacket::new(&buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    let cksum = igmp::checksum(&igmp_aux);

    let mut icmp_pkt = packet::icmp::MutableIcmpPacket::new(&mut buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    icmp_pkt.set_checksum(cksum);

    ip_buf.append(&mut buf);
    let l = ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| {
        FunctionErrorKind::Diagnostic(
            "No possible to create a packet from buffer".to_string(),
            Some(NaslValue::Null),
        )
    })?;
    pkt.set_total_length(l as u16);
    match register.named("update_ip_len") {
        Some(ContextType::Value(NaslValue::Boolean(l))) if !(*l) => {
            pkt.set_total_length(original_ip_len as u16);
        }
        _ => (),
    };
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(NaslValue::Data(ip_buf))
}

fn new_raw_socket() -> Result<Socket, FunctionErrorKind> {
    match Socket::new_raw(
        Domain::IPV4,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    ) {
        Ok(s) => Ok(s),
        Err(e) => Err(FunctionErrorKind::Dirty(format!(
            "Not possible to create a raw socket: {}",
            e
        ))),
    }
}

/// This function tries to open a TCP connection and sees if anything comes back (SYN/ACK or RST).
///  
/// Its argument is:
/// - port: port for the ping
fn nasl_tcp_ping<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
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
    if let Err(e) = soc.set_header_included(true) {
        return Err(FunctionErrorKind::Dirty(format!(
            "Not possible to create a raw socket: {}",
            e
        )));
    };

    // Get the iface name, to set the capture device.
    let target_ip = get_host_ip(configs)?;
    let local_ip = get_source_ip(target_ip, 50000u16)?;
    let iface = get_interface_by_local_ip(local_ip)?;

    let port = match register.named("port") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x,
        None => 0, //TODO: implement plug_get_host_open_port()
        _ => return Err(("Number", "Invalid length value").into()),
    };

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
    let mut ip = MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    ip.set_header_length(5);
    ip.set_fragment_offset(0);
    ip.set_next_level_protocol(IpNextHeaderProtocol(6));
    ip.set_total_length(40);
    ip.set_version(4);
    ip.set_dscp(0);
    ip.set_identification(random_impl()? as u16);
    ip.set_ttl(40);
    let ipv4_src = Ipv4Addr::from_str(&local_ip.to_string())
        .map_err(|_| FunctionErrorKind::WrongArgument("invalid IP".to_string()))?;
    ip.set_source(ipv4_src);
    let ipv4_dst = Ipv4Addr::from_str(&target_ip.to_string())
        .map_err(|_| FunctionErrorKind::WrongArgument("invalid IP".to_string()))?;

    ip.set_destination(ipv4_dst);
    let chksum = checksum(&ip.to_immutable());
    ip.set_checksum(chksum);

    let mut tcp_buf = [0u8; 20];
    let mut tcp = MutableTcpPacket::new(&mut tcp_buf).ok_or_else(|| {
        FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
    })?;
    tcp.set_flags(0x02); //TH_SYN
    tcp.set_sequence(random_impl()? as u32);
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(5);
    tcp.set_window(2048);
    tcp.set_urgent_ptr(0);

    for (i, _) in sports.iter().enumerate() {
        // TODO: the port is fixed since the function to get open ports is not implemented.
        let mut sport = rnd_tcp_port();
        let mut dport = port as u16;
        if port == 0 {
            sport = sports[i];
            dport = ports[i] as u16;
        }

        tcp.set_source(sport);
        tcp.set_destination(dport);
        let chksum = pnet::packet::tcp::ipv4_checksum(
            &tcp.to_immutable(),
            &ip.get_source(),
            &ip.get_destination(),
        );
        tcp.set_checksum(chksum);
        ip.set_payload(tcp.packet());

        let sockaddr = socket2::SockAddr::from(SocketAddr::new(target_ip, 0));
        match soc.send_to(ip.packet(), &sockaddr) {
            Ok(b) => {
                configs.logger().debug(&format!("Sent {} bytes", b));
            }
            Err(e) => {
                return Err(FunctionErrorKind::Dirty(format!("send_packet: {}", e)));
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

/// Send a list of packets, passed as unnamed arguments, with the option to listen to the answers.
///  
/// The arguments are:
/// - Any number of packets to send
/// - length: default length of each every packet, if a packet does not fit, its actual size is taken instead
/// - pcap_active: option to capture the answers, TRUE by default
/// - pcap_filter: BPF filter used for the answers
/// - pcap_timeout: time to wait for the answers in seconds, 5 by default
/// - allow_broadcast: default FALSE
fn nasl_send_packet<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let use_pcap = match register.named("pcap_active") {
        Some(ContextType::Value(NaslValue::Boolean(x))) => *x,
        None => true,
        _ => return Err(("Boolean", "Invalid pcap_active value").into()),
    };

    let filter = match register.named("pcap_filter") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        None => String::new(),
        _ => return Err(("String", "Invalid pcap_filter value").into()),
    };

    let timeout = match register.named("pcap_timeout") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32 * 1000i32, // to milliseconds
        None => DEFAULT_TIMEOUT,
        _ => return Err(("Integer", "Invalid timeout value").into()),
    };

    let mut allow_broadcast = match register.named("allow_broadcast") {
        Some(ContextType::Value(NaslValue::Boolean(x))) => *x,
        None => false,
        _ => return Err(("Boolean", "Invalid allow_broadcast value").into()),
    };

    let positional = register.positional();
    if positional.is_empty() {
        return Ok(NaslValue::Null);
    }

    let soc = new_raw_socket()?;

    if let Err(e) = soc.set_header_included(true) {
        return Err(FunctionErrorKind::Dirty(format!(
            "Not possible to create a raw socket: {}",
            e
        )));
    };

    let _dflt_packet_sz = match register.named("length") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x,
        None => 0,
        _ => return Err(("Number", "Invalid length value").into()),
    };

    // Get the iface name, to set the capture device.
    let target_ip = get_host_ip(configs)?;
    let local_ip = get_source_ip(target_ip, 50000u16)?;
    let iface = get_interface_by_local_ip(local_ip)?;

    let mut capture_dev = match Capture::from_device(iface) {
        Ok(c) => match c.promisc(true).timeout(timeout).open() {
            Ok(capture) => capture,
            Err(e) => return custom_error!("send_packet: {}", e),
        },
        Err(e) => return custom_error!("send_packet: {}", e),
    };

    for pkt in positional.iter() {
        let packet_raw = match pkt {
            NaslValue::Data(data) => data as &[u8],
            _ => return Err(("Data", "Invalid packet").into()),
        };
        let packet = packet::ipv4::Ipv4Packet::new(packet_raw).ok_or_else(|| {
            FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
        })?;

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
            return Err(FunctionErrorKind::Dirty(
                format!("send_packet: malicious or buggy script is trying to send packet to {} instead of designated target {}",
                        packet.get_destination(), target_ip)
            ));
        }

        let sock_str = format!("{}:{}", &packet.get_destination().to_string().as_str(), 0);
        let sockaddr = match SocketAddr::from_str(&sock_str) {
            Ok(addr) => socket2::SockAddr::from(addr),
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!("send_packet: {}", e),
                    Some(NaslValue::Null),
                ));
            }
        };

        match soc.send_to(packet_raw, &sockaddr) {
            Ok(b) => {
                configs.logger().debug(&format!("Sent {} bytes", b));
            }
            Err(e) => {
                return Err(FunctionErrorKind::Diagnostic(
                    format!("send_packet: {}", e),
                    Some(NaslValue::Null),
                ));
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

/// This function is the same as send_capture().
///  
/// - interface: network interface name, by default NASL will try to find the best one
/// - pcap_filter: BPF filter, by default it listens to everything
/// - timeout: timeout in seconds, 5 by default
fn nasl_pcap_next<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    nasl_send_capture(register, configs)
}

/// Read the next packet.
///  
/// - interface: network interface name, by default NASL will try to find the best one
/// - pcap_filter: BPF filter, by default it listens to everything
/// - timeout: timeout in seconds, 5 by default
fn nasl_send_capture<K>(
    register: &Register,
    configs: &Context<K>,
) -> Result<NaslValue, FunctionErrorKind> {
    let interface = match register.named("interface") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        None => String::new(),
        _ => return Err(("String", "Invalid interface value").into()),
    };

    let filter = match register.named("pcap_filter") {
        Some(ContextType::Value(NaslValue::String(x))) => x.to_string(),
        None => String::new(),
        _ => return Err(("String", "Invalid pcap_filter value").into()),
    };

    let timeout = match register.named("pcap_timeout") {
        Some(ContextType::Value(NaslValue::Number(x))) => *x as i32 * 1000i32, // to milliseconds
        None => DEFAULT_TIMEOUT,
        _ => return Err(("Integer", "Invalid timeout value").into()),
    };

    // Get the iface name, to set the capture device.
    let target_ip = get_host_ip(configs)?;
    let local_ip = get_source_ip(target_ip, 50000u16)?;
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
            let frame = EthernetPacket::new(packet.data).ok_or_else(|| {
                FunctionErrorKind::Dirty("No possible to create a packet from buffer".to_string())
            })?;
            return Ok(NaslValue::Data(frame.payload().to_vec()));
        }
        Err(_) => Ok(NaslValue::Null),
    }
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

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "forge_ip_packet" => Some(forge_ip_packet),
        "set_ip_elements" => Some(set_ip_elements),
        "get_ip_element" => Some(get_ip_element),
        "dump_ip_packet" => Some(dump_ip_packet),
        "insert_ip_options" => Some(insert_ip_options),
        "forge_tcp_packet" => Some(forge_tcp_packet),
        "get_tcp_element" => Some(get_tcp_element),
        "get_tcp_option" => Some(get_tcp_option),
        "set_tcp_elements" => Some(set_tcp_elements),
        "insert_tcp_options" => Some(insert_tcp_options),
        "dump_tcp_packet" => Some(dump_tcp_packet),
        "forge_udp_packet" => Some(forge_udp_packet),
        "set_udp_elements" => Some(set_udp_elements),
        "dump_udp_packet" => Some(dump_udp_packet),
        "get_udp_element" => Some(get_udp_element),
        "forge_icmp_packet" => Some(forge_icmp_packet),
        "get_icmp_element" => Some(get_icmp_element),
        "dump_icmp_packet" => Some(dump_icmp_packet),
        "forge_igmp_packet" => Some(forge_igmp_packet),
        "tcp_ping" => Some(nasl_tcp_ping),
        "send_packet" => Some(nasl_send_packet),
        "pcap_next" => Some(nasl_pcap_next),
        "send_capture" => Some(nasl_send_capture),
        _ => None,
    }
}
