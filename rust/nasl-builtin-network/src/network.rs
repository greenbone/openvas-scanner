// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::Command;

use crate::{
    network_utils::{
        get_netmask_by_local_ip, get_source_ip, ipstr2ipaddr, ipv6_parts, islocalhost,
    },
    verify_port,
};
use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};
use nasl_function_proc_macro::nasl_function;
use storage::Kb;

use crate::mtu;

/// Get the IP address of the currently scanned host
#[nasl_function]
fn get_host_ip(context: &Context) -> String {
    context.target().to_string()
}

/// Get the IP address of the current (attacking) machine depending on which network device is used
#[nasl_function]
fn this_host(context: &Context) -> Result<String, FunctionErrorKind> {
    let dst = ipstr2ipaddr(context.target())?;

    let port: u16 = 33435;

    get_source_ip(dst, port).map(|ip| ip.to_string())
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
fn get_mtu() -> i64 {
    mtu() as i64
}

/// check if the currently scanned host is the localhost
#[nasl_function]
fn nasl_islocalhost(context: &Context) -> Result<bool, FunctionErrorKind> {
    let host_ip = ipstr2ipaddr(context.target())?;
    Ok(islocalhost(host_ip))
}

///Check if the target host is on the same network as the attacking host
#[nasl_function]
fn islocalnet(context: &Context) -> Result<bool, FunctionErrorKind> {
    let dst = ipstr2ipaddr(context.target())?;
    let src = get_source_ip(dst, 33435)?;

    let netmask_str = match get_netmask_by_local_ip(src)? {
        Some(netmask) => netmask.to_string(),
        None => return Ok(false),
    };

    let dst_str = dst.to_string();
    let src_str = src.to_string();

    if dst.is_ipv4() {
        let dst_parts: Vec<&str> = dst_str.split('.').collect();
        let src_parts: Vec<&str> = src_str.split('.').collect();
        let netmask_parts: Vec<&str> = netmask_str.split('.').collect();

        // Iterate over each octet
        for i in 0..4 {
            // get octet as u8
            let netmask_part = netmask_parts[i].parse::<u8>().map_err(|_| {
                FunctionErrorKind::Diagnostic(format!("Invalid netmask {}", netmask_str), None)
            })?;
            let dst_part = dst_parts[i].parse::<u8>().map_err(|_| {
                FunctionErrorKind::Diagnostic(format!("Invalid IP address {}", dst_str), None)
            })?;
            let src_part = src_parts[i].parse::<u8>().map_err(|_| {
                FunctionErrorKind::Diagnostic(format!("Invalid IP address {}", src_str), None)
            })?;
            // Iterate over each bit in the octet
            let mut n = 128;
            while n > 0 {
                // If the bit is not set in the netmask, we are done
                if netmask_part & n == 0 {
                    return Ok(true);
                }
                // If the bit is not the same in the source and destination, we are done
                if dst_part & n != src_part & n {
                    return Ok(false);
                }
                n >>= 1;
            }
        }
    } else {
        let dst_parts: Vec<String> = ipv6_parts(&dst_str);
        let src_parts: Vec<String> = ipv6_parts(&src_str);
        let netmask_parts: Vec<String> = ipv6_parts(&netmask_str);

        // Iterate over each IPv6 part
        for i in 0..8 {
            // get part as u16
            let netmask_part = u16::from_str_radix(&netmask_parts[i], 16).map_err(|_| {
                FunctionErrorKind::Diagnostic(format!("Invalid netmask {}", netmask_str), None)
            })?;
            let dst_part = u16::from_str_radix(&dst_parts[i], 16).map_err(|_| {
                FunctionErrorKind::Diagnostic(format!("Invalid IP address {}", dst_str), None)
            })?;
            let src_part = u16::from_str_radix(&src_parts[i], 16).map_err(|_| {
                FunctionErrorKind::Diagnostic(format!("Invalid IP address {}", src_str), None)
            })?;
            // Iterate over each bit in the part
            let mut n = 32768;
            while n > 0 {
                // If the bit is not set in the netmask, we are done
                if netmask_part & n == 0 {
                    return Ok(true);
                }
                // If the bit is not the same in the source and destination, we are done
                if dst_part & n != src_part & n {
                    return Ok(false);
                }
                n >>= 1;
            }
        }
    }

    Ok(true)
}

/// Declares an open port on the target host
#[nasl_function(named(port, proto))]
fn scanner_add_port(
    port: i64,
    protocol: Option<&str>,
    context: &Context,
) -> Result<(), FunctionErrorKind> {
    let port = verify_port(port)?;
    let protocol = protocol.unwrap_or("tcp");

    context.dispatcher().dispatch(
        context.key(),
        storage::Field::KB(Kb {
            key: format!("Port/{}/{}", protocol, port),
            value: storage::types::Primitive::Number(1),
            expire: None,
        }),
    )?;

    Ok(())
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "scanner_add_port" => Some(scanner_add_port),
        "islocalnet" => Some(islocalnet),
        "islocalhost" => Some(nasl_islocalhost),
        "this_host" => Some(this_host),
        "this_host_name" => Some(this_host_name),
        "get_mtu" => Some(get_mtu),
        "get_host_ip" => Some(get_host_ip),
        _ => None,
    }
}

pub struct Network;

impl nasl_builtin_utils::NaslFunctionExecuter for Network {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup(name).is_some()
    }
}
