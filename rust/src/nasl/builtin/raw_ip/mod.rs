// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod denial;
mod frame_forgery;
pub mod packet_forgery;
pub mod raw_ip_utils;
mod synscan;
pub mod tcp_ping;
use std::io;

use crate::nasl::{
    FnError, NaslValue,
    utils::{DefineGlobalVars, IntoFunctionSet, StoredFunctionSet},
};
use denial::Denial;
use frame_forgery::FrameForgery;
use packet_forgery::PacketForgery;
use synscan::SynScan;
use thiserror::Error;

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub enum RawIpError {
    #[error("Failed to get local MAC address.")]
    FailedToGetLocalMacAddress,
    #[error("Failed to get device list.")]
    FailedToGetDeviceList,
    #[error("Failed to get device MTU.")]
    FailedToGetDeviceMTU,
    #[error("Invalid IP address.")]
    InvalidIpAddress,
    #[error("Failed to bind.")]
    FailedToBind(io::Error),
    #[error("No route to destination.")]
    NoRouteToDestination,
    #[error("{0}")]
    PacketForgery(PacketForgeryError),
    #[error("Error sending a packet: {0}")]
    SendPacket(String),
    #[error("{0}")]
    SynScan(SynScanError),
}

#[derive(Debug, Error)]
pub enum SynScanError {
    #[error("{0}")]
    TcpPing(String),
    #[error("No valid Interface: {0}")]
    NoValidInterface(String),
    #[error("Wrong packet length")]
    WrongPacketLength,
    #[error("Invalid EthernetType")]
    InvalidEtherType,
    #[error("Wrong buffer size {0}. Not possible to create an IP packet")]
    CreateIpPacketFromWrongBufferSize(i64),
    #[error("Wrong buffer size {0}. Not possible to create an TCP packet")]
    CreateTcpPacketFromWrongBufferSize(i64),
}

impl From<SynScanError> for FnError {
    fn from(e: SynScanError) -> Self {
        RawIpError::SynScan(e).into()
    }
}

#[derive(Debug, Error)]
pub enum PacketForgeryError {
    #[error("{0}")]
    Custom(String),
    #[error("Failed to parse socket address. {0}")]
    ParseSocketAddr(std::net::AddrParseError),
    #[error("Failed to send packet. {0}")]
    SendPacket(std::io::Error),
    #[error("Failed to create an Ipv4 packet from invalid buffer size.")]
    CreateIpv4Packet,
    #[error("Failed to create an Ipv6 packet from invalid buffer size.")]
    CreateIpv6Packet,
    #[error("Failed to create a TCP packet from invalid buffer size.")]
    CreateTcpPacket,
    #[error("Failed to create a UDP packet from invalid buffer size.")]
    CreateUdpPacket,
    #[error("Failed to create a ICMP packet from invalid buffer size.")]
    CreateIcmpPacket,
}

impl From<PacketForgeryError> for FnError {
    fn from(e: PacketForgeryError) -> Self {
        RawIpError::PacketForgery(e).into()
    }
}

pub struct RawIp;

impl IntoFunctionSet for RawIp {
    type State = RawIp;

    fn into_function_set(self) -> StoredFunctionSet<Self::State> {
        let mut set = StoredFunctionSet::new(self);
        set.add_set(PacketForgery);
        set.add_set(FrameForgery);
        set.add_set(Denial);
        set.add_set(SynScan);
        set
    }
}

impl DefineGlobalVars for RawIp {
    fn get_global_vars() -> Vec<(&'static str, NaslValue)> {
        PacketForgery::get_global_vars()
            .into_iter()
            .chain(FrameForgery::get_global_vars())
            .collect()
    }
}
