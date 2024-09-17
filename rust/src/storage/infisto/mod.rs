// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

mod base;
mod crypto;
mod error;
mod serde;

pub use base::{
    CachedIndexFileStorer, IndexedByteStorage, IndexedByteStorageIterator, IndexedFileStorer, Range,
};
pub use crypto::{ChaCha20IndexFileStorer, Key};
pub use error::Error;
pub use error::IoErrorKind;
pub use serde::Serialization;
