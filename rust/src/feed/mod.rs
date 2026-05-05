// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Handles feed update and verification.
//! A `feed` is a directory of nasl scripts that has at least:
//! - `sha256sums` - a list of files and sha256sums (usually created by executing sha256sum * > sha256sums) and is used to load the various scripts to be updated.
//! - `plugin_feed_info.inc` - feed related information that are read in before running the description mode.
//!
//! A `plugin_feed_info.inc` defines the variables:
//! ```text
//! PLUGIN_SET = "the version of the feed";
//! PLUGIN_FEED = "name of the feed";
//! FEED_VENDOR = "vendor";
//! FEED_HOME = "url the the feed";
//! FEED_NAME = "short name of the feed";
//! ```

mod update;
mod verify;

#[cfg(test)]
mod update_tests;

pub use update::Error as UpdateError;
pub use update::ErrorKind as UpdateErrorKind;
pub use update::Update;
pub use verify::Error as VerifyError;
pub use verify::HashSumFileItem;
pub use verify::HashSumNameLoader;
pub use verify::Hasher;
pub use verify::NoVerifier;
pub use verify::SignatureChecker;
pub use verify::check_signature;
