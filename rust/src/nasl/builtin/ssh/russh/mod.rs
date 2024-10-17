mod error;
mod session;

pub use error::Result;
pub use error::SshError;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

use russh::cipher;
use russh_keys::key;
use session::SshSession;
use tokio::sync::{Mutex, MutexGuard};

use crate::nasl::prelude::*;

use super::MIN_SESSION_ID;

pub type SessionId = i32;
pub type Port = u16;
// TODO: Fix this
pub type Socket = i32;

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

    pub async fn connect(
        &mut self,
        socket: Option<Socket>,
        ip_addr: IpAddr,
        port: Port,
        keytype: Vec<key::Name>,
        csciphers: Vec<cipher::Name>,
        scciphers: Vec<cipher::Name>,
        timeout: Option<Duration>,
    ) -> Result<SessionId> {
        let id = self.next_session_id()?;
        let session = Mutex::new(
            SshSession::new(
                ip_addr, port, timeout, keytype, csciphers, scciphers, socket,
            )
            .await?,
        );
        self.sessions.insert(id, session);
        Ok(id)
    }
}
