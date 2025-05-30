// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// We allow this fow now, since it would require lots of changes
// but should eventually solve this.
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]

#[cfg(feature = "nasl-builtin-raw-ip")]
pub mod alive_test;
pub mod feed;
pub mod models;
pub mod nasl;
pub mod notus;
pub mod openvas;
pub mod osp;
pub mod scanner;
pub mod scheduling;
pub mod storage;
