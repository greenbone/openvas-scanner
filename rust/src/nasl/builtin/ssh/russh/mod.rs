use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use russh::client::Session;
use tokio::sync::{Mutex, MutexGuard};

use crate::nasl::{
    prelude::*,
    utils::{IntoFunctionSet, StoredFunctionSet},
};

use super::error::Result;
use super::{error::SshError, SessionId};

// TODO: Fix this
pub type Socket = i32;

pub type AuthMethods = ();
pub type AuthStatus = ();
pub type LogLevel = ();
pub type SshKey = ();
pub type PublicKeyHashType = ();

pub fn get_log_level() -> LogLevel {
    ()
}

pub enum SshOption {
    LogLevel(LogLevel),
    Hostname(String),
    KnownHosts(Option<String>),
    Timeout(Duration),
    HostKeys(String),
    CiphersCS(String),
    CiphersSC(String),
    Port(u16),
    Socket(Socket),
}

pub struct SshSession {
    session: Session,
    id: SessionId,
}

impl SshSession {
    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn connect(&self) -> Result<()> {
        todo!()
    }

    pub fn disconnect(&self) -> Result<()> {
        todo!()
    }

    pub fn set_option(&self, option: SshOption) -> Result<()> {
        todo!()
        // let formatted = format!("{:?}", option);
        // self.session()
        //     .set_option(option)
        //     .map_err(|e| SshError::SetOption(self.id(), formatted, e))
    }

    fn new(_: SessionId) -> Result<Self> {
        todo!()
    }
}

type BorrowedSession<'a> = MutexGuard<'a, SshSession>;

#[derive(Default)]
pub struct Ssh {
    sessions: HashMap<SessionId, Mutex<SshSession>>,
}

impl Ssh {
    pub async fn get_by_id(&self, id: SessionId) -> Result<BorrowedSession> {
        Ok(self
            .sessions
            .get(&id)
            .ok_or_else(|| SshError::InvalidSessionId(id))?
            .lock()
            .await)
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

    /// Create a new session, but only add it to the list of active sessions
    /// if the given closure which modifies the session returns Ok(...).
    pub async fn add_new_session(
        &mut self,
        f: impl Fn(&mut BorrowedSession) -> Result<()>,
    ) -> Result<SessionId> {
        let id = self.next_session_id()?;
        let session = Mutex::new(SshSession::new(id)?);
        {
            let mut borrowed_session = session.lock().await;
            if let Err(e) = f(&mut borrowed_session) {
                borrowed_session.disconnect()?;
                return Err(e);
            }
        }
        self.sessions.insert(id, session);
        Ok(id)
    }
}
