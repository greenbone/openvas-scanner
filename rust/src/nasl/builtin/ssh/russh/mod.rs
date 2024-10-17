mod error;
mod session;

pub use error::Result;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

use error::SshError;
use russh::cipher;
use russh_keys::key;
use session::SshSession;
use tokio::sync::{Mutex, MutexGuard};

use crate::nasl::{
    prelude::*,
    utils::{function::StringOrData, IntoFunctionSet, StoredFunctionSet},
};

use super::utils::CommaSeparated;

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

    pub async fn add_new_session(
        &mut self,
        port: Port,
        ip_addr: IpAddr,
        timeout: Option<Duration>,
        keytype: Vec<key::Name>,
        csciphers: Vec<cipher::Name>,
        scciphers: Vec<cipher::Name>,
        socket: Option<Socket>,
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

impl Ssh {
    /// Run a command via ssh.
    ///
    /// The function opens a channel to the remote end and ask it to
    /// execute a command.  The output of the command is then returned as a
    /// data block.  The first unnamed argument is the session id. The
    /// command itself is expected as string in the named argument "cmd".
    ///
    /// Regarding the handling of the stderr and stdout stream, this
    /// function may be used in different modes.
    ///
    /// If either the named arguments @a stdout or @a stderr are given and
    /// that one is set to 1, only the output of the specified stream is
    /// returned.
    ///
    /// If stdout and stderr are both given and set to 1, the output
    /// of both is returned interleaved.  NOTE: The following feature has
    /// not yet been implemented: The output is guaranteed not to switch
    /// between stderr and stdout within a line.
    ///
    /// If stdout and stderr are both given but set to 0, a special
    /// backward compatibility mode is used: First all output to stderr is
    /// collected up until any output to stdout is received.  Then all
    /// output to stdout is returned while ignoring all further stderr
    /// output; at EOF the initial collected data from stderr is returned.
    ///
    /// If the named parameters @a stdout and @a stderr are not given, the
    /// function acts exactly as if only @a stdout has been set to 1.
    #[nasl_function(named(cmd, stdout, stderr))]
    async fn nasl_ssh_request_exec(
        &self,
        session_id: SessionId,
        cmd: StringOrData,
        stdout: Option<bool>,
        stderr: Option<bool>,
    ) -> Result<Option<String>> {
        let mut session = self.get_by_id(session_id).await?;
        if cmd.0.is_empty() {
            return Ok(None);
        }
        let (stdout, stderr, compat_mode) = match (stdout, stderr) {
            (None, None) => (true, false, false),
            (Some(false), Some(false)) => (true, false, true),
            (stdout, stderr) => (stdout.unwrap_or(false), stderr.unwrap_or(false), false),
        };
        session
            .call(&cmd.0)
            .await
            .map_err(|e| SshError::CallError(session_id, cmd.0, e))
            .map(|(exit_code, stdout)| Some(stdout))
    }
}

impl IntoFunctionSet for Ssh {
    type State = Ssh;
    fn into_function_set(self) -> StoredFunctionSet<Self::State> {
        let mut set = StoredFunctionSet::new(self);
        set.async_stateful_mut("ssh_connect", Ssh::nasl_ssh_connect);
        set.async_stateful("ssh_request_exec", Ssh::nasl_ssh_request_exec);
        set
    }
}
