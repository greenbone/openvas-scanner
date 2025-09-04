// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod session;

use russh::keys::Algorithm;
pub use session::SshSession;
use tokio::sync::Mutex;

use std::{net::IpAddr, time::Duration};

use super::error::Result;
use russh::cipher;

use super::sessions::SshSessions;

pub type SessionId = i32;
pub type Socket = i32;

type Port = u16;

// This is a 'clone' of the libssh::AuthMethods, so
// the capital case names are intentional.
#[allow(non_camel_case_types, clippy::upper_case_acronyms, unused)]
pub enum AuthMethods {
    PASSWORD,
    INTERACTIVE,
    PUBLIC_KEY,
}

impl SshSessions {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &mut self,
        socket: Option<Socket>,
        ip_addr: IpAddr,
        port: Port,
        keytype: Vec<Algorithm>,
        csciphers: Vec<cipher::Name>,
        scciphers: Vec<cipher::Name>,
        timeout: Option<Duration>,
    ) -> Result<SessionId> {
        let id = self.next_session_id()?;
        let session = Mutex::new(
            SshSession::new(
                id, ip_addr, port, timeout, keytype, csciphers, scciphers, socket,
            )
            .await?,
        );
        self.insert(id, session);
        Ok(id)
    }

    pub async fn disconnect_and_remove(&mut self, session_id: SessionId) -> Result<()> {
        self.remove(session_id)
    }
}
