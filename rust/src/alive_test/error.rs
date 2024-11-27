// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

/// Errors that might occur, when working with the alive test library.
#[derive(Debug, Error)]
pub enum Error {
    /// Not possible to create a socket
    #[error("Not possible to create a socket")]
    NoSocket(String),
    #[error("Not possible to create an ICMP packet")]
    CreateIcmpPacket(String),
    #[error("Invalid destination Address")]
    InvalidDestinationAddr(String),
    #[error("Route unavailable")]
    UnavailableRoute(String),
    #[error("There was an error")]
    Custom(String),
    #[error("pcap error")]
    PcapError(String),
    #[error("send_packet")]
    SendPacket(String),
    #[error("Invalid EtherType")]
    InvalidEtherType(String),
}
