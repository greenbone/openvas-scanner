// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

#[allow(clippy::module_inception)]
mod alive_test;
mod arp;
mod error;
mod icmp;

pub use alive_test::Scanner;
use error::Error as AliveTestError;
