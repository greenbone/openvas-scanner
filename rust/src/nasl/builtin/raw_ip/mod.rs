// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod frame_forgery;
mod packet_forgery;
pub mod raw_ip_utils;
use std::io;

use crate::nasl::utils::{IntoFunctionSet, NaslVars, StoredFunctionSet};
use frame_forgery::FrameForgery;
use packet_forgery::PacketForgery;
pub use packet_forgery::PacketForgeryError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RawIpError {
    #[error("Failed to get local MAC address.")]
    FailedToGetLocalMacAddress,
    #[error("Failed to get device list.")]
    FailedToGetDeviceList,
    #[error("Invalid IP address.")]
    InvalidIpAddress,
    #[error("Failed to bind.")]
    FailedToBind(io::Error),
    #[error("No route to destination.")]
    NoRouteToDestination,
    #[error("{0}")]
    PacketForgery(PacketForgeryError),
}

pub struct RawIp;

impl crate::nasl::utils::NaslVarDefiner for RawIp {
    fn nasl_var_define(&self) -> NaslVars {
        let mut raw_ip_vars = packet_forgery::expose_vars();
        raw_ip_vars.extend(frame_forgery::expose_vars());
        raw_ip_vars
    }
}

impl IntoFunctionSet for RawIp {
    type State = RawIp;

    fn into_function_set(self) -> StoredFunctionSet<Self::State> {
        let mut set = StoredFunctionSet::new(self);
        set.add_set(PacketForgery);
        set.add_set(FrameForgery);
        set
    }
}
