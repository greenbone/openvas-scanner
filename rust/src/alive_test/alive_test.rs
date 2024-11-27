// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::alive_test::AliveTestError;
use crate::models::{AliveTestMethods, Host};

use futures::StreamExt;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use pcap::{Active, Capture, Inactive, PacketCodec, PacketStream};
use pnet::packet::{
    self,
    icmp::*,
    ip::IpNextHeaderProtocol,
    ipv4::{checksum, Ipv4Packet},
};

use socket2::{Domain, Protocol, Socket};

use tracing::debug;

/// Define IPPROTO_RAW
const IPPROTO_RAW: i32 = 255;

/// Default timeout
const DEFAULT_TIMEOUT: u64 = 5000;

enum AliveTestCtl {
    Stop,
    // (IP and succesful detection method)
    Alive(String, AliveTestMethods),
}

fn new_raw_socket() -> Result<Socket, AliveTestError> {
    match Socket::new_raw(
        Domain::IPV4,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    ) {
        Ok(s) => Ok(s),
        Err(_) => Err(AliveTestError::NoSocket("no socket".to_string())),
    }
}

async fn forge_icmp(dst: IpAddr) -> Result<Vec<u8>, AliveTestError> {
    if dst.is_ipv6() {
        return Err(AliveTestError::InvalidDestinationAddr(
            "Invalid destination address".to_string(),
        ));
    }

    let mut buf = vec![0; 8]; // icmp length
    let mut icmp_pkt = packet::icmp::MutableIcmpPacket::new(&mut buf)
        .ok_or_else(|| AliveTestError::CreateIcmpPacket("No icmp packet".to_string()))?;

    icmp_pkt.set_icmp_type(packet::icmp::IcmpTypes::EchoRequest);
    icmp_pkt.set_icmp_code(packet::icmp::IcmpCode::new(0u8));
    let icmp_aux = IcmpPacket::new(&buf)
        .ok_or_else(|| AliveTestError::CreateIcmpPacket("No icmp packet".to_string()))?;
    let chksum = pnet::packet::icmp::checksum(&icmp_aux);

    let mut icmp_pkt = packet::icmp::MutableIcmpPacket::new(&mut buf)
        .ok_or_else(|| AliveTestError::CreateIcmpPacket("No icmp packet".to_string()))?;
    icmp_pkt.set_checksum(chksum);

    let mut ip_buf = vec![0; 20]; //IP length
    ip_buf.append(&mut buf);
    let total_length = ip_buf.len();
    let mut pkt = packet::ipv4::MutableIpv4Packet::new(&mut ip_buf)
        .ok_or_else(|| AliveTestError::CreateIcmpPacket("No icmp packet".to_string()))?;

    pkt.set_header_length(5_u8);
    pkt.set_next_level_protocol(IpNextHeaderProtocol(0x01));
    pkt.set_ttl(255_u8);
    match dst.to_string().parse::<Ipv4Addr>() {
        Ok(ip) => {
            pkt.set_destination(ip);
        }
        Err(_) => {
            return Err(AliveTestError::InvalidDestinationAddr(
                "Invalid destination address".to_string(),
            ));
        }
    };

    pkt.set_version(4u8);
    pkt.set_total_length(total_length as u16);
    let chksum = checksum(&pkt.to_immutable());
    pkt.set_checksum(chksum);

    Ok(ip_buf)
}

/// Send an icmp packet
async fn alive_test_send_icmp_packet(icmp: Vec<u8>) -> Result<(), AliveTestError> {
    tracing::debug!("starting sending packet");
    let soc = new_raw_socket()?;

    if let Err(_) = soc.set_header_included_v4(true) {
        return Err(AliveTestError::NoSocket("no socket".to_string()));
    };

    let icmp_raw = &icmp as &[u8];
    let packet = packet::ipv4::Ipv4Packet::new(icmp_raw).ok_or_else(|| {
        AliveTestError::CreateIcmpPacket("Not possible to create icmp packet".to_string())
    })?;

    let sock_str = format!("{}:{}", &packet.get_destination().to_string().as_str(), 0);
    let sockaddr = SocketAddr::from_str(&sock_str)
        .map_err(|_| AliveTestError::NoSocket("no socket".to_string()))?;
    let sockaddr = socket2::SockAddr::from(sockaddr);

    match soc.send_to(icmp_raw, &sockaddr) {
        Ok(b) => {
            debug!("Sent {} bytes", b);
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
        .timeout(5000)
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    cap.stream(PktCodec)
}

enum EtherTypes {
    EtherTypeIp,
    #[allow(dead_code)]
    EtherTypeIp6,
    #[allow(dead_code)]
    EtherTypeArp,
}

impl TryFrom<&[u8]> for EtherTypes {
    type Error = AliveTestError;

    fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
        match val {
            &[0x08, 0x00] => Ok(EtherTypes::EtherTypeIp),
            &[0x08, 0x06] => Ok(EtherTypes::EtherTypeIp),
            &[0x08, 0xDD] => Ok(EtherTypes::EtherTypeIp),
            _ => Err(AliveTestError::InvalidEtherType(
                "Invalid EtherType".to_string(),
            )),
        }
    }
}

fn process_packet(packet: &[u8]) -> Result<Option<AliveTestCtl>, AliveTestError> {
    if packet.len() <= 16 {
        return Err(AliveTestError::CreateIcmpPacket(
            "Invalid IP packet".to_string(),
        ));
    };
    let ether_type = &packet[14..16];
    let ether_type = EtherTypes::try_from(ether_type)?;
    match ether_type {
        EtherTypes::EtherTypeIp => {
            let pkt = Ipv4Packet::new(&packet[16..])
                .ok_or_else(|| AliveTestError::CreateIcmpPacket("Invalid IP packet".to_string()))?;
            let hl = pkt.get_header_length() as usize;
            if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                let icmp_pkt = IcmpPacket::new(&packet[hl..]).ok_or_else(|| {
                    AliveTestError::CreateIcmpPacket("invalid icmp reply".to_string())
                })?;
                if icmp_pkt.get_icmp_type() == IcmpTypes::EchoReply {
                    if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                        return Ok(Some(AliveTestCtl::Alive(
                            pkt.get_source().to_string(),
                            AliveTestMethods::Icmp,
                        )));
                    }
                }
            }
        }
        EtherTypes::EtherTypeIp6 => unimplemented!(),
        EtherTypes::EtherTypeArp => unimplemented!(),
    }

    Ok(None)
}

pub struct Scanner {
    target: Vec<Host>,
    methods: Vec<AliveTestMethods>,
    timeout: Option<u64>,
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
            self.target.iter().for_each(|t| {
                alive.push((t.clone(), AliveTestMethods::ConsiderAlive.to_string()));
                println!("{t} via {}", AliveTestMethods::ConsiderAlive.to_string())
            });

            return Ok(());
        }

        let capture_inactive = Capture::from_device("any").unwrap();
        let trgt = self.target.clone();

        let (tx_ctl, mut rx_ctl): (mpsc::Sender<AliveTestCtl>, mpsc::Receiver<AliveTestCtl>) =
            mpsc::channel(1024);
        let (tx_msg, mut rx_msg): (mpsc::Sender<AliveTestCtl>, mpsc::Receiver<AliveTestCtl>) =
            mpsc::channel(1024);

        // spawn the process for reading packets from the interfaces.
        let worker_capture_handle = tokio::spawn(async move {
            let mut stream = pkt_stream(capture_inactive).expect("Failed to create stream");
            tracing::debug!("Start capture loop");

            loop {
                tokio::select! {
                    packet = stream.next() => { // packet is Option<Result<Box>>
                        if let Some(Ok(data)) = packet {
                            if let Ok(Some(AliveTestCtl::Alive(addr, method))) = process_packet(&data) {
                                tx_msg.send(AliveTestCtl::Alive(addr, method)).await.unwrap()
                            }
                        }
                    },
                    Some(ctl) = rx_ctl.recv() => {
                        match ctl {
                            AliveTestCtl::Stop =>{
                                break;
                            },
                            _ => ()
                        };
                    },
                }
            }
            tracing::debug!("leaving the capture thread");
        });

        let timeout = if self.timeout.is_some() {
            self.timeout.unwrap()
        } else {
            DEFAULT_TIMEOUT
        };

        let methods = self.methods.clone();
        let worker_handle = tokio::spawn(async move {
            let mut count = 0;

            if methods.contains(&AliveTestMethods::Icmp) {
                for t in trgt.iter() {
                    count += 1;
                    let dst_ip = IpAddr::from_str(t).unwrap();
                    let icmp = forge_icmp(dst_ip).await.unwrap();
                    let _ = alive_test_send_icmp_packet(icmp).await;
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
        });

        while let Some(AliveTestCtl::Alive(addr, method)) = rx_msg.recv().await {
            alive.push((addr.clone(), method.to_string()));
            println!("{addr} via {method:?}");
        }

        let _ = worker_handle.await;
        let _ = worker_capture_handle.await;

        Ok(())
    }
}
