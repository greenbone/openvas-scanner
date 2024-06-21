// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This crate has definitions of internally used lookup keys
//!
//! A lookup key is used to gather script internal information that are not shared
//! between different runs and may be set before running as initial data.

/// _FCT_ANON_ARGS is used to gather unnamed parameter within a function call
pub const FC_ANON_ARGS: &str = "_FCT_ANON_ARGS";
/// _OPENVAS_TARGET is set as the target of the current script run
///
/// In the current version of openvas this information is stored into redis.
/// In the current state of the rust implementation (2023-01-23) we don't have the interface to store data between different script runs.
// Therefore it is currently stored within the register with this key.
pub const TARGET: &str = "_OPENVAS_TARGET";
