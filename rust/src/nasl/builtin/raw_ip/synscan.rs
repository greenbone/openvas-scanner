// Copyright (C) 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL builtin synscan

use pcap::{Active, Capture, Inactive, PacketCodec, PacketStream};
use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket};

use super::SynScanError;
use crate::nasl::NaslValue;
use crate::nasl::prelude::*;
use crate::nasl::raw_ip_utils::{
    raw_ip_utils::{FIX_IPV6_HEADER_LENGTH, send_v4_packet, send_v6_packet},
    tcp_ping::{FILTER_PORT, forge_tcp_ping_ipv4, forge_tcp_ping_ipv6},
};
use crate::nasl::utils::function::utils::DEFAULT_TIMEOUT;
use futures::StreamExt;
use std::collections::BTreeSet;
use std::{collections::HashSet, net::IpAddr, time::Duration};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;

const MIN_ALLOWED_PACKET_LEN: usize = 16;
/// Layer 2 frame offset where the interesting payload start
const L2_FRAME_OFFSET: usize = 16;
const BITS_PER_WORD_IP_HEADER_LEN_INCREMENT: usize = 32;
const BITS_PER_BYTE: usize = 8;

struct PktCodec;

impl PacketCodec for PktCodec {
    type Item = Box<[u8]>;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        packet.data.into()
    }
}

enum EtherTypes {
    EtherTypeIpv4,
    EtherTypeIpv6,
}

impl TryFrom<&[u8]> for EtherTypes {
    type Error = SynScanError;

    fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
        match *val {
            [0x08, 0x00] => Ok(EtherTypes::EtherTypeIpv4),
            [0x86, 0xDD] => Ok(EtherTypes::EtherTypeIpv6),
            _ => Err(SynScanError::InvalidEtherType),
        }
    }
}

fn process_ipv4_packet(packet: &[u8]) -> Result<Option<u16>, SynScanError> {
    let pkt = Ipv4Packet::new(&packet[L2_FRAME_OFFSET..]).ok_or_else(|| {
        SynScanError::CreateIpPacketFromWrongBufferSize((packet.len() - L2_FRAME_OFFSET) as i64)
    })?;
    // IP header length is given in increments of 32 bits
    // Then, the header length in bytes is = hl * 32 bits per words / 8bits per byte;
    let header_len =
        pkt.get_header_length() as usize * BITS_PER_WORD_IP_HEADER_LEN_INCREMENT / BITS_PER_BYTE;
    let l2_and_ip_header = header_len + L2_FRAME_OFFSET;
    if pkt.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        let tcp_packet =
            TcpPacket::new(&packet[l2_and_ip_header..]).ok_or_else(|| {
                SynScanError::CreateTcpPacketFromWrongBufferSize(
                    packet[l2_and_ip_header..].len() as i64
                )
            })?;
        if tcp_packet.get_destination() == FILTER_PORT {
            return Ok(Some(tcp_packet.get_source()));
        };
    }
    Ok(None)
}

fn process_ipv6_packet(packet: &[u8]) -> Result<Option<u16>, SynScanError> {
    let pkt = Ipv6Packet::new(&packet[L2_FRAME_OFFSET..]).ok_or(
        SynScanError::CreateIpPacketFromWrongBufferSize(packet.len() as i64),
    )?;
    if pkt.get_next_header() == IpNextHeaderProtocols::Tcp {
        let tcp_packet = TcpPacket::new(&packet[L2_FRAME_OFFSET + FIX_IPV6_HEADER_LENGTH..])
            .ok_or_else(|| {
                SynScanError::CreateTcpPacketFromWrongBufferSize(
                    packet[L2_FRAME_OFFSET + FIX_IPV6_HEADER_LENGTH..].len() as i64,
                )
            })?;
        if tcp_packet.get_destination() == FILTER_PORT {
            return Ok(Some(tcp_packet.get_source()));
        }
    }
    Ok(None)
}

fn process_packet(packet: &[u8]) -> Result<Option<u16>, SynScanError> {
    if packet.len() <= MIN_ALLOWED_PACKET_LEN {
        return Err(SynScanError::WrongPacketLength);
    };
    // 2 last bytes in the data link layer of ether2 is the ether type (the protocol contained in the payload)
    let ether_type = &packet[14..16];
    let ether_type = EtherTypes::try_from(ether_type)?;
    match ether_type {
        EtherTypes::EtherTypeIpv4 => process_ipv4_packet(packet),
        EtherTypes::EtherTypeIpv6 => process_ipv6_packet(packet),
    }
}

struct SynScanCtlStop;

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

async fn capture_task(
    capture_inactive: Capture<Inactive>,
    mut rx_ctl: Receiver<SynScanCtlStop>,
    tx_msg: Sender<u16>,
) -> Result<(), SynScanError> {
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
                if let Some(SynScanCtlStop) = ctl {
                    break;
                };
            },
        }
    }
    tracing::debug!("leaving the capture thread");
    Ok(())
}

async fn send_task(
    target: IpAddr,
    ports: BTreeSet<u16>,
    timeout: u64,
    tx_ctl: Sender<SynScanCtlStop>,
) -> Result<(), FnError> {
    let mut count = 0;

    for port in ports.iter() {
        count += 1;
        match target {
            IpAddr::V4(ipv4) => {
                let tcp = forge_tcp_ping_ipv4(ipv4, port, pnet::packet::tcp::TcpFlags::SYN)?;
                dbg!(&tcp);
                send_v4_packet(tcp)?;
            }
            IpAddr::V6(ipv6) => {
                let tcp = forge_tcp_ping_ipv6(ipv6, port, pnet::packet::tcp::TcpFlags::SYN)?;
                send_v6_packet(tcp)?;
            }
        };
    }

    tracing::debug!("Finished sending {count} packets");
    sleep(Duration::from_millis(timeout)).await;
    // Send only returns error if the receiver is closed, which only happens when it panics.
    tx_ctl.send(SynScanCtlStop).await.unwrap();
    Ok(())
}

#[nasl_function]
async fn plugin_run_synscan(configs: &ScanCtx<'_>) -> Result<NaslValue, FnError> {
    let target_ip = configs.target().ip_addr().clone();
    let mut open_ports = HashSet::<u16>::new();

    let capture_inactive =
        Capture::from_device("any").map_err(|e| SynScanError::NoValidInterface(e.to_string()))?;

    let (tx_ctl, rx_ctl): (Sender<SynScanCtlStop>, Receiver<SynScanCtlStop>) = mpsc::channel(1024);
    let (tx_msg, mut rx_msg): (Sender<u16>, Receiver<u16>) = mpsc::channel(1024);

    let capture_handle = tokio::spawn(capture_task(capture_inactive, rx_ctl, tx_msg));

    let ports = configs.target().ports_tcp();
    dbg!(ports);
    let send_handle = tokio::spawn(send_task(
        target_ip,
        ports.clone(),
        (DEFAULT_TIMEOUT as u64) * 1000,
        tx_ctl,
    ));

    while let Some(open_port) = rx_msg.recv().await {
        if ports.contains(&open_port) && !open_ports.contains(&open_port) {
            open_ports.insert(open_port);
            println!("{} is open", &open_port);
        }
    }

    send_handle.await.unwrap().unwrap();
    capture_handle.await.unwrap().unwrap();

    Ok(NaslValue::Array(Vec::from_iter(
        open_ports.iter().map(|p| NaslValue::Number(*p as i64)),
    )))
}

pub struct SynScan;

function_set! {
    SynScan,
    (plugin_run_synscan)
}
