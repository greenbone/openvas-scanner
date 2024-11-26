// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL ssh and sftp functions

mod channel;
mod session;

use std::net::{IpAddr, UdpSocket};
use std::{os::fd::AsRawFd, time::Duration};

use libssh_rs::{LogLevel, SshOption};
use russh::cipher;
use russh_keys::key;
use tokio::sync::{Mutex, MutexGuard};
use tracing::debug;

use super::error::Result;
use super::Ssh;

pub use libssh_rs::AuthMethods;
pub use session::SshSession;

pub type SessionId = i32;
pub type Socket = std::os::raw::c_int;

// Currently, our tests are executed with a TRACE filter.  In a normal
// run, this translates to a `LogLevel` of `Functions`, which is very
// verbose.
//
// Since libssh prints its logs to stderr, its output is not filtered
// out by `cargo test`, resulting in tons of annoying output, even if
// the test passes.  To make sure this doesn't happen, we set
// `NoLogging` in all test runs.
#[cfg(test)]
pub fn get_log_level() -> LogLevel {
    LogLevel::NoLogging
}

#[cfg(not(test))]
pub fn get_log_level() -> LogLevel {
    use tracing::Level;
    use tracing_subscriber::filter::LevelFilter;
    let log_level = LevelFilter::current().into_level();
    match log_level {
        None => LogLevel::NoLogging,
        Some(Level::ERROR) | Some(Level::WARN) => LogLevel::Warning,
        Some(Level::INFO) => LogLevel::Protocol,
        Some(Level::DEBUG) => LogLevel::Packet,
        Some(Level::TRACE) => LogLevel::Functions,
    }
}

fn to_comma_separated_string<T: AsRef<str>>(items: &[T]) -> Option<String> {
    if items.is_empty() {
        None
    } else {
        Some(itertools::join(items.iter().map(|name| name.as_ref()), ","))
    }
}

type BorrowedSession<'a> = MutexGuard<'a, SshSession>;

impl Ssh {
    pub async fn find_id<'a>(
        &'a self,
        f: impl for<'b> Fn(&BorrowedSession<'b>) -> bool,
    ) -> Result<Option<SessionId>> {
        for id in self.ids() {
            let session = self.get_by_id(*id).await?;
            if f(&session) {
                return Ok(Some(session.id()));
            }
        }
        Ok(None)
    }

    /// Create a new session, but only add it to the list of active sessions
    /// if the given closure which modifies the session returns Ok(...).
    #[allow(clippy::too_many_arguments)]
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
        let id = self.next_session_id()?;
        let session = Mutex::new(SshSession::new(id)?);
        {
            let mut borrowed_session = session.lock().await;
            if let Err(e) = self
                .try_connect(
                    &mut borrowed_session,
                    socket,
                    ip,
                    port,
                    keytype,
                    csciphers,
                    scciphers,
                    timeout,
                )
                .await
            {
                borrowed_session.disconnect().await?;
                return Err(e);
            }
        }
        self.insert(id, session);
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn try_connect(
        &mut self,
        session: &mut BorrowedSession<'_>,
        socket: Option<Socket>,
        ip: IpAddr,
        port: u16,
        keytype: Vec<key::Name>,
        csciphers: Vec<cipher::Name>,
        scciphers: Vec<cipher::Name>,
        timeout: Option<Duration>,
    ) -> Result<()> {
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
    }

    pub async fn disconnect_and_remove(&mut self, session_id: SessionId) -> Result<()> {
        {
            let mut session = self.get_by_id(session_id).await?;
            session.disconnect().await?;
        }
        self.remove(session_id)
    }
}
