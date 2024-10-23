use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Handle, Msg, Session};
use russh::*;
use server::Auth;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct TestServer {
    clients: Arc<Mutex<HashMap<ChannelId, Handle>>>,
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
        dbg!("OH YEAH");
        let mut clients = self.clients.lock().await;
        clients.insert(channel.id(), session.handle());
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let data = CryptoVec::from(format!("Got data: {}\r\n", String::from_utf8_lossy(data)));
        // Send back
        session.data(channel, data);
        Ok(())
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    /// Called when authentication succeeds for a session.
    #[allow(unused_variables)]
    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client sends a command to execute, to be passed to a
    /// shell. Make sure to check the command before doing so.
    #[allow(unused_variables)]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        panic!();
        Ok(())
    }

    /// The client requests a pseudo-terminal with the given
    /// specifications.
    #[allow(unused_variables, clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
