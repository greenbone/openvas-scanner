mod error;
mod session;

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use error::{Result, SshError};
use session::{SessionConfig, SshSession};
use tokio::sync::{Mutex, MutexGuard};

use crate::nasl::{
    prelude::*,
    utils::{IntoFunctionSet, StoredFunctionSet},
};

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

    pub async fn add_new_session(&mut self, config: SessionConfig) -> Result<SessionId> {
        let id = self.next_session_id()?;
        let session = Mutex::new(
            SshSession::new((config.ip_addr, config.port))
                .await
                .map_err(|e| SshError::Connect(id, e))?,
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
        keytype: Option<&str>,
        csciphers: Option<&str>,
        scciphers: Option<&str>,
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

        let config = SessionConfig::new(port, ip);
        let session_id = self.add_new_session(config).await?;
        // session.set_option(SshOption::LogLevel(get_log_level()))?;
        // session.set_option(SshOption::Hostname(ip_str.to_owned()))?;
        // session.set_option(SshOption::KnownHosts(Some("/dev/null".to_owned())))?;
        // if let Some(timeout) = timeout {
        //     session.set_option(SshOption::Timeout(Duration::from_secs(timeout as u64)))?;
        // }
        // if let Some(keytype) = keytype {
        //     session.set_option(SshOption::HostKeys(keytype.to_owned()))?;
        // }
        // if let Some(csciphers) = csciphers {
        //     session.set_option(SshOption::CiphersCS(csciphers.to_owned()))?;
        // }
        // if let Some(scciphers) = scciphers {
        //     session.set_option(SshOption::CiphersSC(scciphers.to_owned()))?;
        // }
        // if let Some(port) = port {
        //     session.set_option(SshOption::Port(port))?;
        // }

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
}

impl IntoFunctionSet for Ssh {
    type State = Ssh;
    fn into_function_set(self) -> StoredFunctionSet<Self::State> {
        let mut set = StoredFunctionSet::new(self);
        set.async_stateful_mut("ssh_connect", Ssh::nasl_ssh_connect);
        set
    }
}
