// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

/// Errors that might occur, when working with the alive test library.
#[derive(Debug, Error)]
pub enum Error {
    /// Not possible to create a socket
    #[error("Not possible to create a socket: {0}")]
    NoSocket(String),
    #[error("Wrong buffer size {0}. Not possible to create an ICMP packet")]
    CreateIcmpPacketFromWrongBufferSize(i64),
    #[error("Wrong buffer size {0}. Not possible to create an IP packet")]
    CreateIpPacketFromWrongBufferSize(i64),
    #[error("It was not possible to parse the destination Address")]
    InvalidDestinationAddr,
    #[error("Error sending a packet: {0}")]
    SendPacket(String),
    #[error("Invalid EtherType")]
    InvalidEtherType,
    #[error("Wrong packet length")]
    WrongPacketLength,
    #[error("Pcap: No valid interface {0}")]
    NoValidInterface(String),
    #[error("Fail spawning the task {0}")]
    JoinError(String),
}
