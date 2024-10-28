// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines functions and structures for handling sessions

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, UdpSocket};
use std::{os::fd::AsRawFd, time::Duration};

use libssh_rs::{LogLevel, SshOption};
use russh::cipher;
use russh_keys::key;
use tokio::sync::{Mutex, MutexGuard};
use tracing::debug;

use crate::nasl::builtin::ssh::MIN_SESSION_ID;

use super::error::{Result, SshError};
use super::session::SshSession;
use super::{SessionId, Socket};

pub fn get_log_level() -> LogLevel {
    let verbose = std::env::var("OPENVAS_LIBSSH_DEBUG")
        .map(|x| x.parse::<i32>().unwrap_or_default())
        .unwrap_or(0);

    match verbose {
        0 => LogLevel::NoLogging,
        1 => LogLevel::Warning,
        2 => LogLevel::Protocol,
        3 => LogLevel::Packet,
        _ => LogLevel::Functions,
    }
}

fn to_comma_separated_string<T: AsRef<str>>(items: &[T]) -> Option<String> {
    if items.is_empty() {
        None
    } else {
        Some(
            items
                .into_iter()
                .map(|name| name.as_ref().to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

#[derive(Default)]
pub struct Ssh {
    // Unfortunately, we need a Mutex around the SshSession here.
    // This is because it contains a libssh::Channel, which is not `Send`.
    sessions: HashMap<SessionId, Mutex<SshSession>>,
}

type BorrowedSession<'a> = MutexGuard<'a, SshSession>;

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
            let mut borrowed_session = session.lock().await;
            if let Err(e) = f(&mut borrowed_session) {
                borrowed_session.disconnect().await?;
                return Err(e);
            }
        }
        self.sessions.insert(id, session);
        Ok(id)
    }

    pub async fn connect(
        &mut self,
        socket: Option<Socket>,
        ip: IpAddr,
        port: u16,
        keytype: Vec<key::Name>,
        csciphers: Vec<cipher::Name>,
        scciphers: Vec<cipher::Name>,
        timeout: Option<Duration>,
    ) -> Result<SessionId> {
        self.add_new_session(|session| {
            let ip_str = ip.to_string();
            session.set_option(SshOption::LogLevel(get_log_level()))?;
            session.set_option(SshOption::Hostname(ip_str.clone()))?;
            session.set_option(SshOption::KnownHosts(Some("/dev/null".to_owned())))?;
            if let Some(timeout) = timeout {
                session.set_option(SshOption::Timeout(timeout))?;
            }
            if let Some(keytype) = to_comma_separated_string(&keytype) {
                session.set_option(SshOption::HostKeys(keytype))?;
            }
            if let Some(csciphers) = to_comma_separated_string(&csciphers) {
                session.set_option(SshOption::CiphersCS(csciphers))?;
            }
            if let Some(scciphers) = to_comma_separated_string(&scciphers) {
                session.set_option(SshOption::CiphersSC(scciphers))?;
            }
            session.set_option(SshOption::Port(port))?;

            if let Some(socket) = socket {
                // This is a fake raw socket.
                // TODO: implement openvas_get_socket_from_connection()
                let my_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                debug!(
                    ip_str,
                    sock_fd = my_sock.as_raw_fd(),
                    nasl_sock = socket,
                    "Setting SSH fd for socket",
                );
                session.set_option(SshOption::Socket(my_sock.as_raw_fd()))?;
            }
            debug!(
                ip_str,
                port = port,
                socket = socket,
                "Connecting to SSH server",
            );
            session.connect()?;
            Ok(())
        })
        .await
    }

    pub async fn disconnect_and_remove(&mut self, session_id: SessionId) -> Result<()> {
        {
            let mut session = self.get_by_id(session_id).await?;
            session.disconnect().await?;
        }
        self.remove(session_id)
    }
}
