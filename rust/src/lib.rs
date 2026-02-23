// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// We allow this fow now, since it would require lots of changes
// but should eventually solve this.
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
// Allowing this lint on a module basis does not work currently:
// https://github.com/rust-lang/rust/issues/124735
// so we have to allow it library wide.
// See src/nasl/builtin/raw_ip/packet_forgery.rs
#![cfg_attr(feature = "nasl-builtin-raw-ip", allow(unexpected_cfgs))]

#[cfg(feature = "nasl-builtin-raw-ip")]
pub mod alive_test;
pub mod feed;
pub mod nasl;
pub mod notus;
pub mod openvas;
pub mod osp;
pub mod scanner;
pub mod scheduling;
pub mod storage;
pub mod utils;

use std::pin::Pin;

use futures::Stream;
pub use greenbone_scanner_framework::models;

pub type Promise<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub type PromiseRef<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type Streamer<T> = Pin<Box<dyn Stream<Item = T> + Send>>;
pub type ExternalError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub const SQLITE_LIMIT_VARIABLE_NUMBER: usize = 32766;
