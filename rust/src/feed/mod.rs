// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
mod oid;
mod update;
mod verify;

#[cfg(test)]
mod update_tests;

pub use oid::Oid;
pub use update::Error as UpdateError;
pub use update::ErrorKind as UpdateErrorKind;
pub use update::Update;
pub use update::feed_version as version;
pub use verify::Error as VerifyError;
pub use verify::FakeVerifier;
pub use verify::HashSumNameLoader;
pub use verify::Hasher;
pub use verify::SignatureChecker;
pub use verify::check_signature;
