// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Handle, Msg, Session};
use russh::*;
use server::Auth;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AuthConfig {
    pub password: String,
    pub user: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            password: "pass".into(),
            user: "user".into(),
        }
    }
}

#[derive(Clone)]
pub struct TestServer {
    clients: Arc<Mutex<HashMap<ChannelId, Handle>>>,
    auth: AuthConfig,
}

impl TestServer {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            auth: config,
        }
    }
}

#[async_trait]
impl server::Server for TestServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

#[async_trait]
impl server::Handler for TestServer {
    type Error = russh::Error;

    #[allow(clippy::manual_async_fn)]
    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> {
        async move {
            let mut clients = self.clients.lock().await;
            clients.insert(channel.id(), session.handle());
            Ok(true)
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn data(
        &mut self,
        _: ChannelId,
        _: &[u8],
        _: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    #[allow(clippy::manual_async_fn)]
    fn auth_none(&mut self, _user: &str) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::Accept) }
    }

    #[allow(clippy::manual_async_fn)]
    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            if user == self.auth.user && password == self.auth.password {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn auth_succeeded(
        &mut self,
        _: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    #[allow(clippy::manual_async_fn)]
    fn exec_request(
        &mut self,
        channel: ChannelId,
        cmd: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            let _ = match String::from_utf8(cmd.to_vec()).unwrap().as_str() {
                // Send to stdout.
                "write_foo_stdout" => session.data(channel, CryptoVec::from("foo".to_string())),
                // Send to stderr.
                "write_bar_stderr" => {
                    session.extended_data(channel, 1, CryptoVec::from("bar".to_string()))
                }
                "write_both" => {
                    let _ = session.data(channel, CryptoVec::from("foo".to_string()));
                    session.extended_data(channel, 1, CryptoVec::from("bar".to_string()))
                }
                _ => panic!(),
            };
            let _ = session.close(channel);
            Ok(())
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn pty_request(
        &mut self,
        _: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        _: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }

    #[allow(clippy::manual_async_fn)]
    fn shell_request(
        &mut self,
        _: ChannelId,
        _: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async { Ok(()) }
    }
}
