// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{net::IpAddr, process::Command};

use super::socket::SocketError;
use super::{mtu, Port};
use super::{
    network_utils::{get_netmask_by_local_ip, get_source_ip, ipstr2ipaddr, islocalhost},
    DEFAULT_PORT,
};
use crate::function_set;
use crate::nasl::utils::{Context, FnError};
use crate::storage::{types::Primitive, Field, Kb};
use nasl_function_proc_macro::nasl_function;

/// Get the IP address of the currently scanned host
#[nasl_function]
fn get_host_ip(context: &Context) -> String {
    context.target().to_string()
}

/// Get the IP address of the current (attacking) machine depending on which network device is used
#[nasl_function]
fn this_host(context: &Context) -> Result<String, SocketError> {
    let dst = ipstr2ipaddr(context.target())?;

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
fn get_mtu(context: &Context) -> Result<i64, SocketError> {
    let target = ipstr2ipaddr(context.target())?;
    Ok(mtu(target) as i64)
}

/// check if the currently scanned host is the localhost
#[nasl_function]
fn nasl_islocalhost(context: &Context) -> Result<bool, SocketError> {
    let host_ip = ipstr2ipaddr(context.target())?;
    Ok(islocalhost(host_ip))
}

/// Check if the target host is on the same network as the attacking host
#[nasl_function]
fn islocalnet(context: &Context) -> Result<bool, SocketError> {
    let dst = ipstr2ipaddr(context.target())?;
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
fn scanner_add_port(context: &Context, port: Port, proto: Option<&str>) -> Result<(), FnError> {
    let protocol = proto.unwrap_or("tcp");

    context.dispatcher().dispatch(
        context.key(),
        Field::KB(Kb {
            key: format!("Port/{}/{}", protocol, port.0),
            value: Primitive::Number(1),
            expire: None,
        }),
    )?;

    Ok(())
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
    )
}
