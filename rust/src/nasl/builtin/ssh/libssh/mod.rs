// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL ssh and sftp functions

mod channel;
mod session;
pub mod sessions;

pub type SessionId = i32;
pub type Socket = std::os::raw::c_int;
pub use libssh_rs::AuthMethods;
pub use session::SshSession;
