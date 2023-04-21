// Copyright (C) 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines functions and structures for handling sessions

use std::sync::{Arc, Mutex};

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

impl SshSession {
    pub fn new(
        session_id: i32,
        session: Session,
        authmethods: AuthMethods,
        authmethods_valid: bool,
        user_set: bool,
        verbose: i32,
        channel: Option<Channel>,
    ) -> Self {
        Self {
            session_id,
            session,
            authmethods,
            authmethods_valid,
            user_set,
            verbose,
            channel,
        }
    }
}

/// Sessions holder, Holds an array of Tables for different protocols
#[derive(Default)]
pub struct Sessions {
    /// SSH Sessions holder
    pub ssh_sessions: Arc<Mutex<Vec<SshSession>>>,
}

impl Sessions {
    /// Add an SSH session to the Sessions holder
    pub fn add_ssh_session(&self, session: SshSession) {
        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();
        sessions.push(session);
    }
    /// Delete an SSH session to the Sessions holder
    pub fn del_ssh_session(&self, session_id: i32) -> Option<()> {
        let mut sessions = Arc::as_ref(&self.ssh_sessions).lock().unwrap();

        let i = match sessions
            .iter()
            .enumerate()
            .find(|(_i, s)| s.session_id == session_id)
        {
            Some((i, _s)) => i,
            _ => return None,
        };

        sessions.remove(i);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session() {
        let s = Sessions::default();
        s.add_ssh_session(SshSession::default());
        assert_eq!(s.ssh_sessions.as_ref().lock().iter().len(), 1);
    }

    #[test]
    fn delete_session() {
        let st = Sessions::default();
        let s = SshSession::default();
        let id = s.session_id;
        st.add_ssh_session(s);
        assert_eq!(st.del_ssh_session(id), Some(()));
        assert_eq!(st.del_ssh_session(id), None);
    }
}
