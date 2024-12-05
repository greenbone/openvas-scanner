// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::net::{IpAddr, ToSocketAddrs};

use crate::nasl::builtin::HostError;

use super::FnError;

pub fn resolve(mut hostname: String) -> Result<Vec<IpAddr>, FnError> {
    //std::net to_socket_addrs() requires a port. Therefore, using a dummy port
    hostname.push_str(":5000");

    match hostname.to_socket_addrs() {
        Ok(addr) => {
            let ips = addr.into_iter().map(|x| x.ip()).collect::<Vec<_>>();
            Ok(ips)
        }
        // assumes that target is already a hostname
        Err(_) => Err(HostError::TargetIsNotAHostname.into()),
    }
}
