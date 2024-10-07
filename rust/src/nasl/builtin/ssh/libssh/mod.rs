// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// TODO make error handling less redundant
// TODO clean up and maybe split as 2000 lines is a bit much
//! Defines NASL ssh and sftp functions

mod channel;
mod session;
pub mod sessions;

pub use self::sessions::Ssh;
pub type Socket = std::os::raw::c_int;

pub use libssh_rs::{AuthMethods, AuthStatus, LogLevel, SshKey, SshOption};

pub fn get_log_level() -> LogLevel {
    let verbose = std::env::var("OPENVAS_LIBSSH_DEBUG")
        .map(|x| x.parse::<i32>().unwrap_or_default())
        .unwrap_or(0);

    match verbose {
        0 => LogLevel::NoLogging,
        1 => LogLevel::Warning,
        2 => LogLevel::Protocol,
        3 => LogLevel::Packet,
        _ => LogLevel::Functions,
    }
}
