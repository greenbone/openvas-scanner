// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    net::{IpAddr, UdpSocket},
    process::Command,
    str::FromStr,
};

use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};
use nasl_function_proc_macro::nasl_function;

use crate::mtu;

#[nasl_function]
fn this_host(context: &Context) -> Result<String, FunctionErrorKind> {
    let host_ip = context.target();
    if host_ip.is_empty() {
        return Err(FunctionErrorKind::Diagnostic(
            "No target host given".to_string(),
            None,
        ));
    }
    let host_ip = IpAddr::from_str(host_ip).map_err(|_| {
        FunctionErrorKind::Diagnostic(format!("Invalid target IP: {host_ip}"), None)
    })?;

    let port: u16 = 33435;

    let sock = if host_ip.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0")?
    } else {
        UdpSocket::bind("[::]:0")?
    };

    sock.connect((host_ip, port))?;

    Ok(sock.local_addr()?.ip().to_string())
}

#[nasl_function]
fn this_host_name() -> String {
    Command::new("uname")
        .args(["-n"])
        .output()
        .map(|op| String::from_utf8_lossy(&op.stdout).trim().to_string())
        .unwrap_or("".to_string())
}

#[nasl_function]
fn get_mtu() -> i64 {
    mtu() as i64
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
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
