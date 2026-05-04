// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::prelude::*;

const WMI_LIB_IMPLEMENTATION_VERSION: &str = "0.0.1";

#[nasl_function]
fn wmi_versioninfo() -> String {
    WMI_LIB_IMPLEMENTATION_VERSION.to_string()
}

pub struct Wmi;

function_set! {
    Wmi,
    (
       wmi_versioninfo,
    )
}
