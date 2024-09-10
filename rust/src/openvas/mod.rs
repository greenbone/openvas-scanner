// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod cmd;
mod config;
mod error;
#[allow(clippy::module_inception)]
mod openvas;
mod openvas_redis;
mod pref_handler;
mod result_collector;

pub use openvas::Scanner;
