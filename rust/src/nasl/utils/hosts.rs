// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use crate::nasl::builtin::HostError;

use super::FnError;

const DUMMY_PORT: u16 = 5000;
pub const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

pub fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>, FnError> {
    // std::net to_socket_addrs() requires a port. Therefore, using a dummy port
    match (hostname, DUMMY_PORT).to_socket_addrs() {
        Ok(addr) => {
            let ips = addr.into_iter().map(|x| x.ip()).collect::<Vec<_>>();
            Ok(ips)
        }
        // assumes that target is already a hostname
        Err(_) => Err(HostError::TargetIsNotAHostname.into()),
    }
}
