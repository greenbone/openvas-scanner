mod error;
mod session;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use error::{Result, SshError};
use session::SshSession;
use tokio::sync::{Mutex, MutexGuard};
use tracing::debug;

use crate::nasl::{
    prelude::*,
    utils::{IntoFunctionSet, StoredFunctionSet},
};

pub type SessionId = i32;
// TODO: Fix this
pub type Socket = i32;
pub type Port = u16;

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

impl SshSession {
    pub fn set_option(&self, option: SshOption) -> Result<()> {
        todo!("set_option")
        // let formatted = format!("{:?}", option);
        // self.session()
        //     .set_option(option)
        //     .map_err(|e| SshError::SetOption(self.id(), formatted, e))
    }
}
//     fn session(&self) -> &Session {
//         &self.session
//     }

//     pub fn connect(&self) -> Result<()> {
//         todo!()
//     }

//     pub fn disconnect(&self) -> Result<()> {
//         todo!()
//     }

//     fn new(_: SessionId) -> Result<Self> {
//         todo!()
//     }
// }

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
        ip_str: IpAddr,
        port: Port,
        f: impl Fn(&mut BorrowedSession) -> Result<()>,
    ) -> Result<SessionId> {
        let id = self.next_session_id()?;
        let session = Mutex::new(
            SshSession::new((ip_str, port), id)
                .await
                .map_err(|e| SshError::Connect(id, e))?,
        );
        {
            let mut borrowed_session = session.lock().await;
            if let Err(e) = f(&mut borrowed_session) {
                todo!()
                // borrowed_session.disconnect()?;
                // return Err(e);
            }
        }
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
        let port = port.filter(|_| socket.is_none());
        let ip_str: String = match ctx.target() {
            x if !x.is_empty() => x.to_string(),
            _ => "127.0.0.1".to_string(),
        };
        let ip = ip_str.parse::<Ipv4Addr>().unwrap();

        let session_id = self
            .add_new_session(ip.into(), port.unwrap(), |session| {
                Ok(())
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
            })
            .await?;
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
