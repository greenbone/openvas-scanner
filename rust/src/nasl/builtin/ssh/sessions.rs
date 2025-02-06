// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::{HashMap, HashSet};

use tokio::sync::{Mutex, MutexGuard};

use super::error::SshErrorKind;
use super::{error::Result, SessionId, SshSession};

type BorrowedSession<'a> = MutexGuard<'a, SshSession>;

pub const MIN_SESSION_ID: SessionId = 9000;

#[derive(Default)]
pub struct SshSessions {
    // We need a mutex around the `SshSession` here.
    // This is because it contains (depending on feature gates)
    // 1. a libssh::Channel, which is not `Send`.
    // 2. a russh::Channel, which is not `Send`.
    sessions: HashMap<SessionId, Mutex<SshSession>>,
}

impl SshSessions {
    pub async fn get_by_id(&self, id: SessionId) -> Result<BorrowedSession> {
        Ok(self
            .sessions
            .get(&id)
            .ok_or(SshErrorKind::InvalidSessionId.with(id))?
            .lock()
            .await)
    }

    /// Return the next available session ID
    pub fn next_session_id(&self) -> Result<SessionId> {
        // Note that the first session ID we will
        // hand out is an arbitrary high number, this is only to help
        // debugging.
        let taken_ids: HashSet<_> = self.sessions.keys().collect();
        if taken_ids.is_empty() {
            Ok(MIN_SESSION_ID)
        } else {
            let max_val = **taken_ids.iter().max().unwrap() + 1;
            Ok((MIN_SESSION_ID..=max_val)
                .find(|id| !taken_ids.contains(id))
                .unwrap())
        }
    }

    pub fn insert(&mut self, session_id: SessionId, session: Mutex<SshSession>) {
        self.sessions.insert(session_id, session);
    }

    pub fn remove(&mut self, session_id: SessionId) -> Result<()> {
        self.sessions.remove(&session_id);
        Ok(())
    }

    #[cfg(feature = "nasl-builtin-libssh")]
    pub fn ids(&self) -> impl Iterator<Item = &SessionId> {
        self.sessions.keys()
    }
}
