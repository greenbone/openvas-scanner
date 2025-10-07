// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::prelude::*;

#[nasl_function]
fn wmi_versioninfo() -> NaslValue {
    //TODO: once we have a wmi facility, fill this function.
    // We just want to satisfy toolcheck.nasl for now.
    NaslValue::Null
}

#[nasl_function]
fn smb_versioninfo() -> NaslValue {
    //TODO: once we have a wmi facility, fill this function.
    // We just want to satisfy toolcheck.nasl for now.
    NaslValue::Null
}

#[derive(Default)]
pub struct Wmi;

function_set! {
    Wmi,
    (
        wmi_versioninfo,
        smb_versioninfo,
    )
}
