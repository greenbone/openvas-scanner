// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::Command;

use crate::network_utils::{get_netmask_by_local_ip, get_source_ip, ipstr2ipaddr, islocalhost};
use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};
use nasl_function_proc_macro::nasl_function;

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

        for i in 0..4 {
            if netmask_parts[i] == "0" {
                return Ok(true);
            }
            if dst_parts[i] != src_parts[i] {
                return Ok(false);
            }
        }
    } else {
        let dst_parts: Vec<&str> = dst_str.split(':').collect();
        let src_parts: Vec<&str> = src_str.split(':').collect();
        let netmask_parts: Vec<&str> = netmask_str.split(':').collect();

        for i in 0..8 {
            if netmask_parts[i] == "ffff" {
                return Ok(true);
            }
            if dst_parts[i] != src_parts[i] {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "islocalnet" => Some(islocalnet),
        "islocalhost" => Some(nasl_islocalhost),
        "this_host" => Some(this_host),
        "this_host_name" => Some(this_host_name),
        "get_mtu" => Some(get_mtu),
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
