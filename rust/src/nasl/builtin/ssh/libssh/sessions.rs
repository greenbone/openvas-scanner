// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines functions and structures for handling sessions

use std::collections::HashSet;

use std::sync::{Arc, Mutex, MutexGuard};

use crate::nasl::builtin::ssh::SessionId;

use super::super::error::{Result, SshError};
use super::session::{BorrowedSession, SshSession};

#[derive(Default)]
pub struct Ssh {
    sessions: Arc<Mutex<Vec<SshSession>>>,
}

impl Ssh {
    fn lock(&self) -> Result<MutexGuard<Vec<SshSession>>> {
        self.sessions.lock().map_err(|_| SshError::PoisonedLock)
    }

    pub fn get_by_id(&self, id: SessionId) -> Result<BorrowedSession> {
        let guard = self.lock()?;
        BorrowedSession::new(guard, id)
    }

    /// Return the next available session ID
    fn next_session_id(&self) -> Result<SessionId> {
        // Note that the first session ID we will
        // hand out is an arbitrary high number, this is only to help
        // debugging.
        const MIN_VAL: SessionId = 9000;
        let taken_ids = self
            .lock()?
            .iter()
            .map(|session| session.id)
            .collect::<HashSet<SessionId>>();
        if taken_ids.is_empty() {
            Ok(MIN_VAL)
        } else {
            let max_val = taken_ids.iter().max().unwrap() + 1;
            Ok((MIN_VAL..=max_val)
                .find(|id| !taken_ids.contains(id))
                .unwrap())
        }
    }

    pub fn remove(&self, session_id: SessionId) -> Result<()> {
        let mut guard = self.lock()?;
        if let Some((index, _)) = guard
            .iter()
            .enumerate()
            .find(|(_, session)| session.id == session_id)
        {
            guard.remove(index);
        }
        Ok(())
    }

    pub fn find<'a>(
        &'a self,
        f: impl for<'b> Fn(&BorrowedSession<'b>) -> bool,
    ) -> Result<Option<BorrowedSession<'a>>> {
        // This is a pretty ugly implementation but the borrow checker
        // (somewhat rightfully) makes this quite hard to do normally.
        let mut guard = self.lock()?;
        let len = guard.len();
        for i in 0..len {
            let session = BorrowedSession::from_index(guard, i);
            if f(&session) {
                return Ok(Some(session));
            }
            guard = session.take_guard();
        }
        Ok(None)
    }

    /// Create a new session, but only add it to the list of active sessions
    /// if the given closure which modifies the session returns Ok(...).
    pub fn add_new_session(
        &self,
        f: impl Fn(&mut BorrowedSession) -> Result<()>,
    ) -> Result<SessionId> {
        let id = self.next_session_id()?;
        let mut guard = self.lock()?;
        let index = guard.len();
        let session = SshSession::new(id)?;
        guard.push(session);
        let mut session = BorrowedSession::from_index(guard, index);
        let result = f(&mut session);
        match result {
            Ok(()) => Ok(id),
            Err(e) => {
                session.disconnect()?;
                session.take_guard().pop();
                Err(e)
            }
        }
    }
}
