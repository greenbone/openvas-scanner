// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// TODO make error handling less redundant
// TODO clean up and maybe split as 2000 lines is a bit much
//! Defines NASL ssh and sftp functions

mod channel;
mod error;
mod session;
pub mod sessions;

pub use self::sessions::Ssh;

pub type SessionId = i32;
pub type Socket = std::os::raw::c_int;
pub use error::SshError;
