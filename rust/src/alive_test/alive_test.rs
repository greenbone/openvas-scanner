// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::alive_test::AliveTestError;
use crate::models::{AliveTestMethods, Host};

use futures::StreamExt;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use pcap::{Active, Capture, Inactive, PacketCodec, PacketStream};
use pnet::packet::{
    self,
    icmp::{IcmpCode, IcmpTypes, MutableIcmpPacket, *},
    ip::IpNextHeaderProtocol,
    ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
};

use socket2::{Domain, Protocol, Socket};

const IPPROTO_RAW: i32 = 255;
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const ICMP_LENGTH: usize = 8;
const IP_LENGTH: usize = 20;
const HEADER_LENGTH: u8 = 5;
const DEFAULT_TTL: u8 = 255;
const MIN_ALLOWED_PACKET_LEN: usize = 16;
enum AliveTestCtl {
    Stop,
    // (IP and successful detection method)
    Alive {
        ip: String,
        detection_method: AliveTestMethods,
    },
}
fn make_mut_icmp_packet(buf: &mut Vec<u8>) -> Result<MutableIcmpPacket, AliveTestError> {
    MutableIcmpPacket::new(buf).ok_or_else(|| AliveTestError::CreateIcmpPacket)
}

fn new_raw_socket() -> Result<Socket, AliveTestError> {
    Socket::new_raw(
        Domain::IPV4,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    )
    .map_err(|e| AliveTestError::NoSocket(e.to_string()))
}

fn forge_icmp(dst: IpAddr) -> Result<Vec<u8>, AliveTestError> {
    if dst.is_ipv6() {
        return Err(AliveTestError::InvalidDestinationAddr);
    }

    // Create an icmp packet from a buffer and modify it.
    let mut buf = vec![0; ICMP_LENGTH];
    let mut icmp_pkt = make_mut_icmp_packet(&mut buf)?;
    icmp_pkt.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_pkt.set_icmp_code(IcmpCode::new(0u8));

    // Require an unmutable ICMP packet for checksum calculation.
    // We create an unmutable from the buffer for this purpose
    let icmp_aux = IcmpPacket::new(&buf).ok_or_else(|| AliveTestError::CreateIcmpPacket)?;
    let chksum = pnet::packet::icmp::checksum(&icmp_aux);

    // Because the buffer of original mutable icmp packet is borrowed,
    // create a new mutable icmp packet to set the checksum in the original buffer.
    let mut icmp_pkt = make_mut_icmp_packet(&mut buf)?;
    icmp_pkt.set_checksum(chksum);

    // We do now the same as above for the IPv4 packet, appending the icmp packet as payload
    let mut ip_buf = vec![0; IP_LENGTH];
    ip_buf.append(&mut buf);
    let total_length = ip_buf.len();
    let mut pkt =
        MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| AliveTestError::CreateIcmpPacket)?;

    pkt.set_header_length(HEADER_LENGTH);
    pkt.set_next_level_protocol(IpNextHeaderProtocol(IpNextHeaderProtocols::Icmp.0));
    pkt.set_ttl(DEFAULT_TTL);
    match dst.to_string().parse::<Ipv4Addr>() {
        Ok(ip) => {
            pkt.set_destination(ip);
        }
        Err(_) => {
            return Err(AliveTestError::InvalidDestinationAddr);
        }
    };

    pkt.set_version(4u8);
    pkt.set_total_length(total_length as u16);
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(ip_buf)
}

/// Send an icmp packet
fn alive_test_send_icmp_packet(icmp: Vec<u8>) -> Result<(), AliveTestError> {
    tracing::debug!("starting sending packet");
    let sock = new_raw_socket()?;
    sock.set_header_included_v4(true)
        .map_err(|e| AliveTestError::NoSocket(e.to_string()))?;

    let icmp_raw = &icmp as &[u8];
    let packet =
        packet::ipv4::Ipv4Packet::new(icmp_raw).ok_or_else(|| AliveTestError::CreateIcmpPacket)?;

    let sockaddr = SocketAddr::new(IpAddr::V4(packet.get_destination()), 0);
    match sock.send_to(icmp_raw, &sockaddr.into()) {
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
        match val {
            &[0x08, 0x00] => Ok(EtherTypes::EtherTypeIp),
            &[0x08, 0x06] => Ok(EtherTypes::EtherTypeArp),
            &[0x08, 0xDD] => Ok(EtherTypes::EtherTypeIp6),
            _ => Err(AliveTestError::InvalidEtherType),
        }
    }
}

fn process_ip_packet(packet: &[u8]) -> Result<Option<AliveTestCtl>, AliveTestError> {
    let pkt = Ipv4Packet::new(&packet[16..]).ok_or_else(|| AliveTestError::CreateIcmpPacket)?;
    let hl = pkt.get_header_length() as usize;
    if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        let icmp_pkt =
            IcmpPacket::new(&packet[hl..]).ok_or_else(|| AliveTestError::CreateIcmpPacket)?;
        if icmp_pkt.get_icmp_type() == IcmpTypes::EchoReply {
            if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                return Ok(Some(AliveTestCtl::Alive {
                    ip: pkt.get_source().to_string(),
                    detection_method: AliveTestMethods::Icmp,
                }));
            }
        }
    }
    Ok(None)
}

fn process_packet(packet: &[u8]) -> Result<Option<AliveTestCtl>, AliveTestError> {
    if packet.len() <= MIN_ALLOWED_PACKET_LEN {
        return Err(AliveTestError::WrongPacketLength);
    };
    let ether_type = &packet[14..16];
    let ether_type = EtherTypes::try_from(ether_type)?;
    match ether_type {
        EtherTypes::EtherTypeIp => process_ip_packet(&packet),
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
    mut rx_ctl: Receiver<AliveTestCtl>,
    tx_msg: Sender<AliveTestCtl>,
) -> Result<(), AliveTestError> {
    let mut stream = pkt_stream(capture_inactive).expect("Failed to create stream");
    tracing::debug!("Start capture loop");

    loop {
        tokio::select! {
            packet = stream.next() => { // packet is Option<Result<Box>>
                if let Some(Ok(data)) = packet {
                    if let Ok(Some(AliveTestCtl::Alive{ip: addr, detection_method: method})) = process_packet(&data) {
                        tx_msg.send(AliveTestCtl::Alive{ip: addr, detection_method: method}).await.unwrap()
                    }
                }
            },
            ctl = rx_ctl.recv() => {
                if let Some(AliveTestCtl::Stop) = ctl {
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
    tx_ctl: Sender<AliveTestCtl>,
) -> Result<(), AliveTestError> {
    let mut count = 0;

    if methods.contains(&AliveTestMethods::Icmp) {
        for t in trgt.iter() {
            count += 1;
            let dst_ip = IpAddr::from_str(t).expect("Valid IP address");
            let icmp = forge_icmp(dst_ip).expect("Valid ICMP packet");
            let _ = alive_test_send_icmp_packet(icmp);
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
    let _ = tx_ctl.send(AliveTestCtl::Stop).await;
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
        let mut alive = Vec::<(String, String)>::new();

        if self.methods.contains(&AliveTestMethods::ConsiderAlive) {
            for t in self.target.iter() {
                alive.push((t.clone(), AliveTestMethods::ConsiderAlive.to_string()));
                println!("{t} via {}", AliveTestMethods::ConsiderAlive.to_string())
            }
            return Ok(());
        };

        let capture_inactive = Capture::from_device("any")
            .map_err(|e| AliveTestError::NoValidInterface(e.to_string()))?;
        let trgt = self.target.clone();

        let (tx_ctl, rx_ctl): (Sender<AliveTestCtl>, Receiver<AliveTestCtl>) = mpsc::channel(1024);
        let (tx_msg, mut rx_msg): (Sender<AliveTestCtl>, Receiver<AliveTestCtl>) =
            mpsc::channel(1024);

        let capture_handle = tokio::spawn(capture_task(capture_inactive, rx_ctl, tx_msg));

        let timeout = self.timeout.unwrap_or(DEFAULT_TIMEOUT_MS);
        let methods = self.methods.clone();
        let send_handle = tokio::spawn(send_task(methods, trgt, timeout, tx_ctl));

        while let Some(AliveTestCtl::Alive {
            ip: addr,
            detection_method: method,
        }) = rx_msg.recv().await
        {
            alive.push((addr.clone(), method.to_string()));
            println!("{addr} via {method:?}");
        }

        match send_handle.await {
            Ok(Ok(())) => (),
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(AliveTestError::JoinError(e.to_string())),
        };
        match capture_handle.await {
            Ok(Ok(())) => (),
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(AliveTestError::JoinError(e.to_string())),
        };

        Ok(())
    }
}
