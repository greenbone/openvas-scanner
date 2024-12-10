// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{net::IpAddr, process::Command};

use super::socket::SocketError;
use super::{
    DEFAULT_PORT,
    network_utils::{get_netmask_by_local_ip, get_source_ip, islocalhost},
};
use super::{NaslValue, Port, mtu};
use crate::function_set;
use crate::nasl::utils::{FnError, ScanCtx};
use crate::storage::items::kb::{self, KbItem, KbKey};
use nasl_function_proc_macro::nasl_function;

/// Get the IP address of the currently scanned host
#[nasl_function]
fn get_host_ip(context: &ScanCtx) -> String {
    context.target().ip_addr().to_string()
}

/// Get the IP address of the current (attacking) machine depending on which network device is used
#[nasl_function]
fn this_host(context: &ScanCtx) -> Result<String, SocketError> {
    let dst = context.target().ip_addr();

    let port: u16 = DEFAULT_PORT;

    get_source_ip(dst, port)
        .map(|ip| ip.to_string())
        .map_err(|_| SocketError::NoRouteToDestination(dst))
}

/// Get the host name of the current (attacking) machine
#[nasl_function]
fn this_host_name() -> String {
    Command::new("uname")
        .args(["-n"])
        .output()
        .map(|op| String::from_utf8_lossy(&op.stdout).trim().to_string())
        .unwrap_or("".to_string())
}

/// get the maximum transition unit for the scanned host
#[nasl_function]
fn get_mtu(context: &ScanCtx) -> Result<i64, SocketError> {
    Ok(mtu(context.target().ip_addr()) as i64)
}

/// check if the currently scanned host is the localhost
#[nasl_function]
fn nasl_islocalhost(context: &ScanCtx) -> Result<bool, SocketError> {
    let host_ip = context.target().ip_addr();
    Ok(islocalhost(host_ip))
}

/// Check if the target host is on the same network as the attacking host
#[nasl_function]
fn islocalnet(context: &ScanCtx) -> Result<bool, SocketError> {
    let dst = context.target().ip_addr();
    let src = get_source_ip(dst, DEFAULT_PORT)?;
    let netmask = match get_netmask_by_local_ip(src)? {
        Some(netmask) => netmask,
        None => return Ok(false),
    };

    match dst {
        IpAddr::V4(dst) => {
            let src = match src {
                IpAddr::V4(src) => src,
                IpAddr::V6(_) => unreachable!(),
            };
            let netmask = match netmask {
                IpAddr::V4(netmask) => netmask,
                IpAddr::V6(_) => unreachable!(),
            };
            let dst_parts = dst.octets();
            let src_parts = src.octets();
            let netmask_parts = netmask.octets();

            // Iterate over each octet of the address
            for i in 0..4 {
                // Iterate over each bit in the octet
                let mut n = 128;
                while n > 0 {
                    // If the bit is not set in the netmask, we are done
                    if netmask_parts[i] & n == 0 {
                        return Ok(true);
                    }
                    // If the bit is not the same in the source and destination, we are done
                    if dst_parts[i] & n != src_parts[i] & n {
                        return Ok(false);
                    }
                    n >>= 1;
                }
            }
        }
        IpAddr::V6(dst) => {
            let src = match src {
                IpAddr::V4(_) => unreachable!(),
                IpAddr::V6(src) => src,
            };
            let netmask = match netmask {
                IpAddr::V4(_) => unreachable!(),
                IpAddr::V6(netmask) => netmask,
            };
            let dst_parts = dst.segments();
            let src_parts = src.segments();
            let netmask_parts = netmask.segments();

            // Iterate over each segment of the address
            for i in 0..8 {
                // Iterate over each bit in the segment
                let mut n = 32768;
                while n > 0 {
                    // If the bit is not set in the netmask, we are done
                    if netmask_parts[i] & n == 0 {
                        return Ok(true);
                    }
                    // If the bit is not the same in the source and destination, we are done
                    if dst_parts[i] & n != src_parts[i] & n {
                        return Ok(false);
                    }
                    n >>= 1;
                }
            }
        }
    }
    Ok(false)
}

/// Declares an open port on the target host
#[nasl_function(named(port, proto))]
fn scanner_add_port(context: &ScanCtx, port: Port, proto: Option<&str>) -> Result<(), FnError> {
    let kb_key = match proto {
        Some("udp") => KbKey::Port(kb::Port::Udp(port.0.to_string())),
        _ => KbKey::Port(kb::Port::Tcp(port.0.to_string())),
    };

    context.set_single_kb_item(kb_key, KbItem::Number(1))?;

    Ok(())
}

#[nasl_function]
fn scanner_get_port(context: &ScanCtx, idx: u16) -> Result<NaslValue, FnError> {
    let ports = context.target().ports_tcp().iter().collect::<Vec<&u16>>();
    if (idx as usize) < ports.len() {
        return Ok(NaslValue::Number(*ports[idx as usize] as i64));
    }

    Ok(NaslValue::Null)
}

#[nasl_function]
fn get_host_open_port(context: &ScanCtx) -> i64 {
    context.get_random_open_tcp_port().unwrap_or_default() as i64
}

#[nasl_function(named(asstring))]
fn get_port_transport(context: &ScanCtx, port: u16, asstring: bool) -> Result<NaslValue, FnError> {
    let transport = context.get_port_transport(port).unwrap_or(1);
    let ret = if asstring {
        let transport_str = match transport {
            0 => "auto".to_string(),
            1 => "IP".to_string(),
            3 => "SSLv2".to_string(),
            2 => "SSLv23".to_string(),
            4 => "SSLv3".to_string(),
            5 => "TLSv1".to_string(),
            6 => "TLSv11".to_string(),
            7 => "TLSv12".to_string(),
            8 => "TLSv13".to_string(),
            9 => "TLScustom".to_string(),
            _ => format!("[unknown transport layer - code {transport} (0x{transport:x})]"),
        };
        NaslValue::String(transport_str)
    } else {
        NaslValue::Number(transport)
    };

    Ok(ret)
}

#[nasl_function]
fn get_port_state(context: &ScanCtx, port: u16) -> Result<bool, FnError> {
    context.get_port_state(port, crate::models::Protocol::TCP)
}

#[nasl_function]
fn get_udp_port_state(context: &ScanCtx, port: u16) -> Result<bool, FnError> {
    context.get_port_state(port, crate::models::Protocol::UDP)
}

pub struct Network;

function_set! {
    Network,
    (
        scanner_add_port,
        islocalnet,
        (nasl_islocalhost, "islocalhost"),
        this_host,
        this_host_name,
        get_mtu,
        get_host_ip,
        get_host_open_port,
        get_port_transport,
        scanner_get_port,
        get_port_state,
        (get_port_state, "get_tcp_port_state"),
        get_udp_port_state,
    )
}
