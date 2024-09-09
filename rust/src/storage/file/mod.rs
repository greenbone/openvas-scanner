// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

pub mod base;
pub mod crypto;
mod error;
pub mod serde;

pub use error::Error;
pub use error::IoErrorKind;
