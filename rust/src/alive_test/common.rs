// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use socket2::{Domain, Protocol, Socket};

use super::AliveTestError;

const IPPROTO_RAW: i32 = 255;

pub fn new_raw_socket() -> Result<Socket, AliveTestError> {
    Socket::new_raw(
        Domain::IPV4,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    )
    .map_err(|e| AliveTestError::NoSocket(e.to_string()))
}

pub fn new_raw_socket_v6() -> Result<Socket, AliveTestError> {
    Socket::new_raw(
        Domain::IPV6,
        socket2::Type::RAW,
        Some(Protocol::from(IPPROTO_RAW)),
    )
    .map_err(|e| AliveTestError::NoSocket(e.to_string()))
}
