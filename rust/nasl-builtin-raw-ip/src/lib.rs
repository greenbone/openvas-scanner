// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod frame_forgery;
mod packet_forgery;
mod raw_ip_utils;
use frame_forgery::FrameForgery;
use nasl_builtin_utils::{IntoFunctionSet, NaslVars, StoredFunctionSet};
use packet_forgery::PacketForgery;

pub struct RawIp;

impl nasl_builtin_utils::NaslVarDefiner for RawIp {
    fn nasl_var_define(&self) -> NaslVars {
        let mut raw_ip_vars = packet_forgery::expose_vars();
        raw_ip_vars.extend(frame_forgery::expose_vars());
        raw_ip_vars
    }
}

impl IntoFunctionSet for RawIp {
    type Set = StoredFunctionSet<RawIp>;

    fn into_function_set(self) -> Self::Set {
        let mut set = StoredFunctionSet::new(self);
        set.add_set(PacketForgery);
        set.add_set(FrameForgery);
        set
    }
}
