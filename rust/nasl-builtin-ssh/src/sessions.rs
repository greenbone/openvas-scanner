// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines functions and structures for handling sessions

use libssh_rs::{AuthMethods, Channel, Session};

/// Structure to hold an SSH Session
pub struct SshSession {
    /// Session ID
    pub session_id: i32,
    /// Ssh Session
    pub session: Session,
    /// Hold the available authentication methods
    pub authmethods: AuthMethods,
    /// Indicating that methods is valid
    pub authmethods_valid: bool,
    /// Set if a user has been set for the session
    pub user_set: bool,
    /// Verbose diagnostic
    pub verbose: i32,
    /// Channel
    pub channel: Option<Channel>,
}

impl Default for SshSession {
    fn default() -> Self {
        {
            Self {
                session_id: 50000,
                session: Session::new().unwrap(),
                authmethods: AuthMethods::NONE,
                authmethods_valid: false,
                user_set: false,
                verbose: 0,
                channel: None,
            }
        }
    }
}
