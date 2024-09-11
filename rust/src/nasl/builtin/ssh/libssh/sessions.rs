// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines functions and structures for handling sessions

use std::collections::{HashMap, HashSet};

use tokio::sync::Mutex;

use crate::nasl::builtin::ssh::SessionId;

use super::super::error::{Result, SshError};
use super::session::{BorrowedSession, SshSession};

#[derive(Default)]
pub struct Ssh {
    // Unfortunately, we need a Mutex around the SshSession here.
    // This is because it contains a libssh::Channel, which is not `Send`.
    sessions: HashMap<SessionId, Mutex<SshSession>>,
}

impl Ssh {
    pub async fn get_by_id(&self, id: SessionId) -> Result<BorrowedSession> {
        Ok(BorrowedSession::new(
            self.sessions
                .get(&id)
                .ok_or_else(|| SshError::InvalidSessionId(id))?
                .lock()
                .await,
        ))
    }

    /// Return the next available session ID
    fn next_session_id(&self) -> Result<SessionId> {
        // Note that the first session ID we will
        // hand out is an arbitrary high number, this is only to help
        // debugging.
        const MIN_VAL: SessionId = 9000;
        let taken_ids: HashSet<_> = self.sessions.keys().collect();
        if taken_ids.is_empty() {
            Ok(MIN_VAL)
        } else {
            let max_val = **taken_ids.iter().max().unwrap() + 1;
            Ok((MIN_VAL..=max_val)
                .find(|id| !taken_ids.contains(id))
                .unwrap())
        }
    }

    pub fn remove(&mut self, session_id: SessionId) -> Result<()> {
        self.sessions.remove(&session_id);
        Ok(())
    }

    pub async fn find_id<'a>(
        &'a self,
        f: impl for<'b> Fn(&BorrowedSession<'b>) -> bool,
    ) -> Result<Option<SessionId>> {
        for id in self.sessions.keys() {
            let session = self.get_by_id(*id).await?;
            if f(&session) {
                return Ok(Some(session.id()));
            }
        }
        Ok(None)
    }

    /// Create a new session, but only add it to the list of active sessions
    /// if the given closure which modifies the session returns Ok(...).
    pub async fn add_new_session(
        &mut self,
        f: impl Fn(&mut BorrowedSession) -> Result<()>,
    ) -> Result<SessionId> {
        let id = self.next_session_id()?;
        let session = Mutex::new(SshSession::new(id)?);
        {
            let mut borrowed_session = BorrowedSession::new(session.lock().await);
            if let Err(e) = f(&mut borrowed_session) {
                borrowed_session.disconnect()?;
                return Err(e);
            }
        }
        self.sessions.insert(id, session);
        Ok(id)
    }
}
