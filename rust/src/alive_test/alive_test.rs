// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::alive_test::AliveTestError;
use crate::models::{AliveTestMethods, Host};

use futures::StreamExt;
use pnet::packet::icmp;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use pcap::{Active, Capture, Inactive, PacketCodec, PacketStream};
use pnet::packet::{
    icmp::{IcmpCode, IcmpTypes, MutableIcmpPacket, *},
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
    Packet,
};

use socket2::{Domain, Protocol, Socket};

const IPPROTO_RAW: i32 = 255;
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const ICMP_LENGTH: usize = 8;
const IP_LENGTH: usize = 20;
const HEADER_LENGTH: u8 = 5;
const DEFAULT_TTL: u8 = 255;
const MIN_ALLOWED_PACKET_LEN: usize = 16;
// This is the only possible code for an echo request
const ICMP_ECHO_REQ_CODE: u8 = 0;
const IP_PPRTO_VERSION_IPV4: u8 = 4;

pub struct AliveTestCtlStop;

pub struct AliveHostCtl {
    ip: String,
    detection_method: AliveTestMethods,
}
impl AliveHostCtl {
    fn new(ip: String, detection_method: AliveTestMethods) -> Self {
        Self {
            ip,
            detection_method,
        }
    }
}

fn new_raw_socket() -> Result<Socket, AliveTestError> {
    Socket::new_raw(
        Domain::IPV4,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    )
    .map_err(|e| AliveTestError::NoSocket(e.to_string()))
}

fn forge_icmp_packet() -> Vec<u8> {
    // Create an icmp packet from a buffer and modify it.
    let mut buf = vec![0; ICMP_LENGTH];
    // Since we control the buffer size, we can safely unwrap here.
    let mut icmp_pkt = MutableIcmpPacket::new(&mut buf).unwrap();
    icmp_pkt.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_pkt.set_icmp_code(IcmpCode::new(ICMP_ECHO_REQ_CODE));
    icmp_pkt.set_checksum(icmp::checksum(&icmp_pkt.to_immutable()));
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

fn forge_icmp(dst: Ipv4Addr) -> Ipv4Packet<'static> {
    let mut icmp_buf = forge_icmp_packet();
    forge_ipv4_packet_for_icmp(&mut icmp_buf, dst)
}

/// Send an icmp packet
fn alive_test_send_icmp_packet(icmp: Ipv4Packet<'static>) -> Result<(), AliveTestError> {
    tracing::debug!("starting sending packet");
    let sock = new_raw_socket()?;
    sock.set_header_included_v4(true)
        .map_err(|e| AliveTestError::NoSocket(e.to_string()))?;

    let sockaddr = SocketAddr::new(IpAddr::V4(icmp.get_destination()), 0);
    match sock.send_to(icmp.packet(), &sockaddr.into()) {
        Ok(b) => {
            tracing::debug!("Sent {} bytes", b);
        }
        Err(e) => {
            return Err(AliveTestError::SendPacket(e.to_string()));
        }
    };
    Ok(())
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
        .timeout(DEFAULT_TIMEOUT_MS as i32)
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    cap.stream(PktCodec)
}

enum EtherTypes {
    EtherTypeIp,
    EtherTypeIp6,
    EtherTypeArp,
}

impl TryFrom<&[u8]> for EtherTypes {
    type Error = AliveTestError;

    fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
        match *val {
            [0x08, 0x00] => Ok(EtherTypes::EtherTypeIp),
            [0x08, 0x06] => Ok(EtherTypes::EtherTypeArp),
            [0x08, 0xDD] => Ok(EtherTypes::EtherTypeIp6),
            _ => Err(AliveTestError::InvalidEtherType),
        }
    }
}

fn process_ip_packet(packet: &[u8]) -> Result<Option<AliveHostCtl>, AliveTestError> {
    let pkt = Ipv4Packet::new(&packet[16..]).ok_or_else(|| {
        AliveTestError::CreateIpPacketFromWrongBufferSize(packet.len() as i64 - 16)
    })?;
    let hl = pkt.get_header_length() as usize;
    if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        let icmp_pkt = IcmpPacket::new(&packet[hl..]).ok_or_else(|| {
            AliveTestError::CreateIcmpPacketFromWrongBufferSize(packet[hl..].len() as i64)
        })?;
        if icmp_pkt.get_icmp_type() == IcmpTypes::EchoReply
            && pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp
        {
            return Ok(Some(AliveHostCtl {
                ip: pkt.get_source().to_string(),
                detection_method: AliveTestMethods::Icmp,
            }));
        }
    }
    Ok(None)
}

fn process_packet(packet: &[u8]) -> Result<Option<AliveHostCtl>, AliveTestError> {
    if packet.len() <= MIN_ALLOWED_PACKET_LEN {
        return Err(AliveTestError::WrongPacketLength);
    };
    let ether_type = &packet[14..16];
    let ether_type = EtherTypes::try_from(ether_type)?;
    match ether_type {
        EtherTypes::EtherTypeIp => process_ip_packet(packet),
        EtherTypes::EtherTypeIp6 => unimplemented!(),
        EtherTypes::EtherTypeArp => unimplemented!(),
    }
}

pub struct Scanner {
    target: Vec<Host>,
    methods: Vec<AliveTestMethods>,
    timeout: Option<u64>,
}

async fn capture_task(
    capture_inactive: Capture<Inactive>,
    mut rx_ctl: Receiver<AliveTestCtlStop>,
    tx_msg: Sender<AliveHostCtl>,
) -> Result<(), AliveTestError> {
    let mut stream = pkt_stream(capture_inactive).expect("Failed to create stream");
    tracing::debug!("Start capture loop");

    loop {
        tokio::select! {
            packet = stream.next() => { // packet is Option<Result<Box>>
                if let Some(Ok(data)) = packet {
                    if let Ok(Some(alive_host)) = process_packet(&data) {
                        tx_msg.send(alive_host).await.unwrap()
                    }
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
    trgt: Vec<String>,
    timeout: u64,
    tx_ctl: Sender<AliveTestCtlStop>,
) -> Result<(), AliveTestError> {
    let mut count = 0;

    if methods.contains(&AliveTestMethods::Icmp) {
        for t in trgt.iter() {
            count += 1;
            let dst_ip = match t.to_string().parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => {
                    continue;
                }
            };
            let icmp = forge_icmp(dst_ip);
            alive_test_send_icmp_packet(icmp)?;
        }
    }
    if methods.contains(&AliveTestMethods::TcpSyn) {
        //unimplemented
    }
    if methods.contains(&AliveTestMethods::TcpAck) {
        //unimplemented
    }
    if methods.contains(&AliveTestMethods::Arp) {
        //unimplemented
    }

    tracing::debug!("Finished sending {count} packets");
    sleep(Duration::from_millis(timeout)).await;
    // Send only returns error if the receiver is closed, which only happens when it panics.
    tx_ctl.send(AliveTestCtlStop).await.unwrap();
    Ok(())
}

impl Scanner {
    pub fn new(target: Vec<Host>, methods: Vec<AliveTestMethods>, timeout: Option<u64>) -> Self {
        Self {
            target,
            methods,
            timeout,
        }
    }

    pub async fn run_alive_test(&self) -> Result<(), AliveTestError> {
        // TODO: Replace with a Storage type to store the alive host list
        let mut alive = Vec::<AliveHostCtl>::new();

        if self.methods.contains(&AliveTestMethods::ConsiderAlive) {
            for t in self.target.iter() {
                alive.push(AliveHostCtl::new(
                    t.clone(),
                    AliveTestMethods::ConsiderAlive,
                ));
                println!("{t} via {}", AliveTestMethods::ConsiderAlive)
            }
            return Ok(());
        };

        let capture_inactive = Capture::from_device("any")
            .map_err(|e| AliveTestError::NoValidInterface(e.to_string()))?;
        let trgt = self.target.clone();
        let (tx_ctl, rx_ctl): (Sender<AliveTestCtlStop>, Receiver<AliveTestCtlStop>) =
            mpsc::channel(1024);
        let (tx_msg, mut rx_msg): (Sender<AliveHostCtl>, Receiver<AliveHostCtl>) =
            mpsc::channel(1024);

        let capture_handle = tokio::spawn(capture_task(capture_inactive, rx_ctl, tx_msg));

        let timeout = self.timeout.unwrap_or(DEFAULT_TIMEOUT_MS);
        let methods = self.methods.clone();
        let send_handle = tokio::spawn(send_task(methods, trgt, timeout, tx_ctl));

        while let Some(AliveHostCtl {
            ip: addr,
            detection_method: method,
        }) = rx_msg.recv().await
        {
            alive.push(AliveHostCtl::new(addr.clone(), method.clone()));
            println!("{addr} via {method:?}");
        }

        send_handle.await.unwrap().unwrap();
        capture_handle.await.unwrap().unwrap();

        Ok(())
    }
}
