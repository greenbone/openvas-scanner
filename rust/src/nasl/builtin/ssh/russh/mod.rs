mod error;
mod session;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

use error::{Result, SshError};
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

const DEFAULT_SSH_PORT: u16 = 22;

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
    #[nasl_function(named(socket, port, keytype, csciphers, scciphers, timeout))]
    async fn nasl_ssh_connect(
        &mut self,
        socket: Option<Socket>,
        port: Option<u16>,
        keytype: Option<CommaSeparated<key::Name>>,
        csciphers: Option<CommaSeparated<cipher::Name>>,
        scciphers: Option<CommaSeparated<cipher::Name>>,
        timeout: Option<u64>,
        ctx: &Context<'_>,
    ) -> Result<SessionId> {
        let port = port
            .filter(|_| socket.is_none())
            .unwrap_or(DEFAULT_SSH_PORT);
        let ip_str: String = match ctx.target() {
            x if !x.is_empty() => x.to_string(),
            _ => "127.0.0.1".to_string(),
        };
        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|e| SshError::InvalidIpAddr(ip_str.clone(), e))?;
        let timeout = timeout.map(|timeout| Duration::from_secs(timeout as u64));

        let keytype = keytype
            .map(|keytype| keytype.0)
            .unwrap_or(russh::Preferred::DEFAULT.key[..].to_vec());
        let csciphers = csciphers
            .map(|cscipher| cscipher.0)
            .unwrap_or(russh::Preferred::DEFAULT.cipher[..].to_vec());
        let scciphers = scciphers
            .map(|sccipher| sccipher.0)
            .unwrap_or(russh::Preferred::DEFAULT.cipher[..].to_vec());

        let session_id = self
            .add_new_session(port, ip, timeout, keytype, csciphers, scciphers, socket)
            .await?;
        // if let Some(socket) = socket {
        //     todo!()
        //     // // This is a fake raw socket.
        //     // // TODO: implement openvas_get_socket_from_connection()
        //     // let my_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        //     // debug!(
        //     //     ip_str = ip_str,
        //     //     sock_fd = my_sock.as_raw_fd(),
        //     //     nasl_sock = socket,
        //     //     "Setting SSH fd for socket",
        //     // );
        //     // session.set_option(SshOption::Socket(my_sock.as_raw_fd()))?;
        // }
        // debug!(
        //     ip_str = ip_str,
        //     port = port,
        //     socket = socket,
        //     "Connecting to SSH server",
        // );
        // session.connect()?;
        // Ok(())
        Ok(session_id)
    }

    /// Write the string `cmd` to an ssh shell.
    #[nasl_function]
    async fn nasl_ssh_shell_write(&self, session_id: SessionId, cmd: StringOrData) -> Result<i32> {
        let mut session = self.get_by_id(session_id).await?;
        session
            .call(&cmd.0)
            .await
            .map(|exit_code| exit_code as i32)
            .map_err(|e| SshError::CallError(session_id, cmd.0, e))
    }
}

impl IntoFunctionSet for Ssh {
    type State = Ssh;
    fn into_function_set(self) -> StoredFunctionSet<Self::State> {
        let mut set = StoredFunctionSet::new(self);
        set.async_stateful_mut("ssh_connect", Ssh::nasl_ssh_connect);
        set.async_stateful("ssh_shell_write", Ssh::nasl_ssh_shell_write);
        set
    }
}
