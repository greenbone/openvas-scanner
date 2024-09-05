// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

pub mod loader;
pub mod packages;

pub mod error;
pub mod notus;
pub mod vts;

#[cfg(test)]
mod tests;
