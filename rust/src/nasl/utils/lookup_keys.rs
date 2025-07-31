// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This crate has definitions of internally used lookup keys
//!
//! A lookup key is used to gather script internal information that are not shared
//! between different runs and may be set before running as initial data.

/// _FCT_ANON_ARGS is used to gather unnamed parameter within a function call
pub const FC_ANON_ARGS: &str = "_FCT_ANON_ARGS";

/// _SCRIPT_PARAMS is used to gather script parameters within a function call
pub const SCRIPT_PARAMS: &str = "_SCRIPT_PARAMS";
