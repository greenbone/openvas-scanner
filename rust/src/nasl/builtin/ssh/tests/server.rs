use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Handle, Msg, Session};
use russh::*;
use server::Auth;
use tokio::sync::Mutex;

const EXEC_REQUEST_RESPONSE: &str = "foo";

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

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut clients = self.clients.lock().await;
        clients.insert(channel.id(), session.handle());
        Ok(true)
    }

    async fn data(&mut self, _: ChannelId, _: &[u8], _: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.auth.user && password == self.auth.password {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn auth_succeeded(&mut self, _: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Send back the same string every time
        let data = CryptoVec::from(EXEC_REQUEST_RESPONSE.to_string());
        session.data(channel, data);
        session.close(channel);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        _: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn shell_request(&mut self, _: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }
}
