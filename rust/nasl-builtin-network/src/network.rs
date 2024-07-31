// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::Command;

use nasl_builtin_utils::{Context, NaslFunction, Register};
use nasl_function_proc_macro::nasl_function;

use crate::mtu;

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
