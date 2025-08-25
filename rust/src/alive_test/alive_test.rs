// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::alive_test::AliveTestError;
use crate::alive_test::arp::forge_arp_request;
use crate::alive_test::common::{alive_test_send_v4_packet, alive_test_send_v6_packet};
use crate::alive_test::icmp::{forge_icmp_v4, forge_icmp_v6, forge_neighbor_solicit};
use crate::alive_test::tcp_ping::{FILTER_PORT, forge_tcp_ping_ipv4, forge_tcp_ping_ipv6};

use crate::models::{AliveTestMethods, Host};
use crate::nasl::utils::function::utils::DEFAULT_TIMEOUT;

use futures::StreamExt;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;

use std::net::IpAddr;

use pcap::{Active, Capture, Inactive, PacketCodec, PacketStream};
use pnet::packet::{
    icmp::{IcmpTypes, *},
    ipv4::Ipv4Packet,
};

use super::common::FIX_IPV6_HEADER_LENGTH;

const DEFAULT_PORT_LIST: [u16; 20] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080,
];

const MIN_ALLOWED_PACKET_LEN: usize = 16;
/// Layer 2 frame offset where the interesting payload start
const L2_FRAME_OFFSET: usize = 16;
const BITS_PER_WORD_IP_HEADER_LEN_INCREMENT: usize = 32;
const BITS_PER_BYTE: usize = 8;

struct AliveTestCtlStop;

#[derive(Clone)]
pub struct AliveHostInfo {
    ip: String,
    detection_method: AliveTestMethods,
}

struct PktCodec;

impl PacketCodec for PktCodec {
    type Item = Box<[u8]>;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        packet.data.into()
    }
}

fn pkt_stream(
    capture_inactive: Capture<Inactive>,
) -> Result<PacketStream<Active, PktCodec>, pcap::Error> {
    let cap = capture_inactive
        .promisc(true)
        .immediate_mode(true)
        .timeout(DEFAULT_TIMEOUT * 1000)
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    cap.stream(PktCodec)
}

enum EtherTypes {
    EtherTypeIpv4,
    EtherTypeIpv6,
    EtherTypeArp,
}

impl TryFrom<&[u8]> for EtherTypes {
    type Error = AliveTestError;

    fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
        match *val {
            [0x08, 0x00] => Ok(EtherTypes::EtherTypeIpv4),
            [0x08, 0x06] => Ok(EtherTypes::EtherTypeArp),
            [0x86, 0xDD] => Ok(EtherTypes::EtherTypeIpv6),
            _ => Err(AliveTestError::InvalidEtherType),
        }
    }
}

fn process_ipv4_packet(packet: &[u8]) -> Result<Option<AliveHostInfo>, AliveTestError> {
    let pkt = Ipv4Packet::new(&packet[L2_FRAME_OFFSET..]).ok_or_else(|| {
        AliveTestError::CreateIpPacketFromWrongBufferSize((packet.len() - L2_FRAME_OFFSET) as i64)
    })?;
    // IP header length is given in increments of 32 bits
    // Then, the header length in bytes is = hl * 32 bits per words / 8bits per byte;
    let header_len =
        pkt.get_header_length() as usize * BITS_PER_WORD_IP_HEADER_LEN_INCREMENT / BITS_PER_BYTE;
    let l2_and_ip_header = header_len + L2_FRAME_OFFSET;
    if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        let icmp_pkt = IcmpPacket::new(&packet[l2_and_ip_header..]).ok_or_else(|| {
            AliveTestError::CreateIcmpPacketFromWrongBufferSize(
                packet[l2_and_ip_header..].len() as i64
            )
        })?;
        if icmp_pkt.get_icmp_type() == IcmpTypes::EchoReply
            && pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp
        {
            return Ok(Some(AliveHostInfo {
                ip: pkt.get_source().to_string(),
                detection_method: AliveTestMethods::Icmp,
            }));
        }
    }
    if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        let tcp_packet = TcpPacket::new(&packet[l2_and_ip_header..]).ok_or_else(|| {
            AliveTestError::CreateIcmpPacketFromWrongBufferSize(
                packet[l2_and_ip_header..].len() as i64
            )
        })?;
        if tcp_packet.get_destination() == FILTER_PORT {
            return Ok(Some(AliveHostInfo {
                ip: pkt.get_source().to_string(),
                detection_method: AliveTestMethods::TcpSyn,
            }));
        }
    }
    Ok(None)
}

fn process_ipv6_packet(packet: &[u8]) -> Result<Option<AliveHostInfo>, AliveTestError> {
    let pkt = Ipv6Packet::new(&packet[L2_FRAME_OFFSET..]).ok_or(
        AliveTestError::CreateIpPacketFromWrongBufferSize(packet.len() as i64),
    )?;
    if pkt.get_next_header() == IpNextHeaderProtocols::Icmpv6 {
        let icmp_pkt = Icmpv6Packet::new(&packet[L2_FRAME_OFFSET + FIX_IPV6_HEADER_LENGTH..])
            .ok_or_else(|| {
                AliveTestError::CreateIcmpPacketFromWrongBufferSize(packet[..].len() as i64)
            })?;

        let make_alive_host_ctl = |pkt: Ipv6Packet<'_>, method| {
            Ok(Some(AliveHostInfo {
                ip: pkt.get_source().to_string(),
                detection_method: method,
            }))
        };
        match icmp_pkt.get_icmpv6_type() {
            Icmpv6Types::EchoReply => return make_alive_host_ctl(pkt, AliveTestMethods::Icmp),
            Icmpv6Types::NeighborAdvert => return make_alive_host_ctl(pkt, AliveTestMethods::Arp),
            _ => {}
        }
    }
    if pkt.get_next_header() == IpNextHeaderProtocols::Tcp {
        let tcp_packet = TcpPacket::new(&packet[L2_FRAME_OFFSET + FIX_IPV6_HEADER_LENGTH..])
            .ok_or_else(|| {
                AliveTestError::CreateTcpPacketFromWrongBufferSize(
                    packet[L2_FRAME_OFFSET + FIX_IPV6_HEADER_LENGTH..].len() as i64,
                )
            })?;
        if tcp_packet.get_destination() == FILTER_PORT {
            return Ok(Some(AliveHostInfo {
                ip: pkt.get_source().to_string(),
                detection_method: AliveTestMethods::TcpSyn,
            }));
        }
    }
    Ok(None)
}

fn process_arp_frame(frame: &[u8]) -> Result<Option<AliveHostInfo>, AliveTestError> {
    let arp = ArpPacket::new(&frame[L2_FRAME_OFFSET..]).ok_or(
        AliveTestError::CreateIpPacketFromWrongBufferSize(frame.len() as i64),
    )?;
    if arp.get_operation() == ArpOperations::Reply {
        return Ok(Some(AliveHostInfo {
            ip: arp.get_sender_proto_addr().to_string(),
            detection_method: AliveTestMethods::Arp,
        }));
    }
    Ok(None)
}

fn process_packet(packet: &[u8]) -> Result<Option<AliveHostInfo>, AliveTestError> {
    if packet.len() <= MIN_ALLOWED_PACKET_LEN {
        return Err(AliveTestError::WrongPacketLength);
    };
    // 2 last bytes in the data link layer of ether2 is the ether type (the protocol contained in the payload)
    let ether_type = &packet[14..16];
    let ether_type = EtherTypes::try_from(ether_type)?;
    match ether_type {
        EtherTypes::EtherTypeIpv4 => process_ipv4_packet(packet),
        EtherTypes::EtherTypeIpv6 => process_ipv6_packet(packet),
        EtherTypes::EtherTypeArp => process_arp_frame(packet),
    }
}

pub struct Scanner {
    target: HashSet<Host>,
    methods: Vec<AliveTestMethods>,
    timeout: Option<u64>,
}

async fn capture_task(
    capture_inactive: Capture<Inactive>,
    mut rx_ctl: Receiver<AliveTestCtlStop>,
    tx_msg: Sender<AliveHostInfo>,
) -> Result<(), AliveTestError> {
    let mut stream = pkt_stream(capture_inactive).expect("Failed to create stream");
    tracing::debug!("Start capture loop");

    loop {
        tokio::select! {
            packet = stream.next() => { // packet is Option<Result<Box>>
                if let Some(Ok(data)) = packet && let Ok(Some(alive_host)) = process_packet(&data) {
                        tx_msg.send(alive_host).await.unwrap()
                }
            },
            ctl = rx_ctl.recv() => {
                if let Some(AliveTestCtlStop) = ctl {
                    break;
                };
            },
        }
    }
    tracing::debug!("leaving the capture thread");
    Ok(())
}

async fn send_task(
    methods: Vec<AliveTestMethods>,
    target: HashSet<String>,
    timeout: u64,
    tx_ctl: Sender<AliveTestCtlStop>,
) -> Result<(), AliveTestError> {
    let mut count = 0;

    let target: HashSet<IpAddr> = target
        .into_iter()
        .map(|val| {
            val.parse::<IpAddr>()
                .map_err(|e| AliveTestError::InvalidDestinationAddr(e.to_string()))
        })
        .collect::<Result<_, _>>()?;

    if methods.contains(&AliveTestMethods::Icmp) {
        for t in target.iter() {
            count += 1;
            match t {
                IpAddr::V4(ipv4) => {
                    let icmp = forge_icmp_v4(*ipv4);
                    alive_test_send_v4_packet(icmp)?;
                }
                IpAddr::V6(ipv6) => {
                    let icmp = forge_icmp_v6(*ipv6)?;
                    alive_test_send_v6_packet(icmp)?;
                }
            }
        }
    }
    if methods.contains(&AliveTestMethods::TcpSyn) {
        for t in target.iter() {
            for port in DEFAULT_PORT_LIST.iter() {
                count += 1;
                match t {
                    IpAddr::V4(ipv4) => {
                        let tcp =
                            forge_tcp_ping_ipv4(*ipv4, port, pnet::packet::tcp::TcpFlags::SYN)?;
                        alive_test_send_v4_packet(tcp)?;
                    }
                    IpAddr::V6(ipv6) => {
                        let tcp =
                            forge_tcp_ping_ipv6(*ipv6, port, pnet::packet::tcp::TcpFlags::SYN)?;
                        alive_test_send_v6_packet(tcp)?;
                    }
                };
            }
        }
    }
    if methods.contains(&AliveTestMethods::TcpAck) {
        for t in target.iter() {
            for port in DEFAULT_PORT_LIST.iter() {
                count += 1;
                match t {
                    IpAddr::V4(ipv4) => {
                        let tcp =
                            forge_tcp_ping_ipv4(*ipv4, port, pnet::packet::tcp::TcpFlags::ACK)?;
                        alive_test_send_v4_packet(tcp)?;
                    }
                    IpAddr::V6(ipv6) => {
                        let tcp =
                            forge_tcp_ping_ipv6(*ipv6, port, pnet::packet::tcp::TcpFlags::ACK)?;
                        alive_test_send_v6_packet(tcp)?;
                    }
                };
            }
        }
    }
    if methods.contains(&AliveTestMethods::Arp) {
        for t in target.iter() {
            count += 1;
            match t {
                IpAddr::V4(ipv4) => {
                    forge_arp_request(*ipv4)?;
                }
                IpAddr::V6(ipv6) => {
                    let ndp = forge_neighbor_solicit(*ipv6)?;
                    alive_test_send_v6_packet(ndp)?;
                }
            };
        }
    }

    tracing::debug!("Finished sending {count} packets");
    sleep(Duration::from_millis(timeout)).await;
    // Send only returns error if the receiver is closed, which only happens when it panics.
    tx_ctl.send(AliveTestCtlStop).await.unwrap();
    Ok(())
}

impl Scanner {
    pub fn new(
        target: HashSet<Host>,
        methods: Vec<AliveTestMethods>,
        timeout: Option<u64>,
    ) -> Self {
        Self {
            target,
            methods,
            timeout,
        }
    }

    pub async fn run_alive_test(&self) -> Result<HashSet<String>, AliveTestError> {
        // TODO: Replace with a Storage type to store the alive host list
        let mut alive = HashSet::<String>::new();

        if self.methods.contains(&AliveTestMethods::ConsiderAlive) {
            for t in self.target.iter() {
                alive.insert(t.clone());
                println!("{t} via {}", AliveTestMethods::ConsiderAlive)
            }
            return Ok(alive);
        };

        let capture_inactive = Capture::from_device("any")
            .map_err(|e| AliveTestError::NoValidInterface(e.to_string()))?;
        let trgt = self.target.clone();
        let (tx_ctl, rx_ctl): (Sender<AliveTestCtlStop>, Receiver<AliveTestCtlStop>) =
            mpsc::channel(1024);
        let (tx_msg, mut rx_msg): (Sender<AliveHostInfo>, Receiver<AliveHostInfo>) =
            mpsc::channel(1024);

        let capture_handle = tokio::spawn(capture_task(capture_inactive, rx_ctl, tx_msg));

        let timeout = self.timeout.unwrap_or((DEFAULT_TIMEOUT * 1000) as u64);
        let methods = self.methods.clone();
        let send_handle = tokio::spawn(send_task(methods, trgt, timeout, tx_ctl));

        while let Some(alivehost) = rx_msg.recv().await {
            if self.target.contains(&alivehost.ip) && !alive.contains(&alivehost.ip) {
                alive.insert(alivehost.ip.clone());
                println!("{} via {:?}", &alivehost.ip, &alivehost.detection_method);
            }
        }

        send_handle.await.unwrap().unwrap();
        capture_handle.await.unwrap().unwrap();

        Ok(alive)
    }
}
