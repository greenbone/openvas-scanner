use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Handle, Msg, Session};
use russh::*;
use server::{run_stream, Auth, Config};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct TestServer {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), Handle>>>,
    id: usize,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            ..Default::default()
        }
    }

    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for ((id, channel), ref mut s) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }
}

#[async_trait]
impl server::Server for TestServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }

    // /// We can vastly simplify the actual server main loop here by basically
    // /// unwrapping everything (since this is a test context) and only accepting
    // /// a single connection.
    // async fn run_on_socket(
    //     &mut self,
    //     config: Arc<Config>,
    //     socket: &TcpListener,
    // ) -> Result<(), std::io::Error> {
    //     let (socket, _) = socket.accept().await.unwrap();
    //     let config = config.clone();
    //     let handler = self.new_client(socket.peer_addr().ok());
    //     tokio::spawn(async move {
    //         run_stream(config, socket, handler)
    //             .await
    //             .unwrap()
    //             .await
    //             .unwrap();
    //     });
    //     Ok(())
    // }
}

#[async_trait]
impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert((self.id, channel.id()), session.handle());
        }
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }

        let data = CryptoVec::from(format!("Got data: {}\r\n", String::from_utf8_lossy(data)));
        self.post(data.clone()).await;
        session.data(channel, data);
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let handle = session.handle();
        let address = address.to_string();
        let port = *port;
        tokio::spawn(async move {
            let channel = handle
                .channel_open_forwarded_tcpip(address, port, "1.2.3.4", 1234)
                .await
                .unwrap();
            let _ = channel.data(&b"Hello from a forwarded port"[..]).await;
            let _ = channel.eof().await;
        });
        Ok(true)
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    // #[allow(unused_variables)]
    // async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
    //     todo!("2");
    // }

    // #[allow(unused_variables)]
    // async fn auth_publickey_offered(
    //     &mut self,
    //     user: &str,
    //     public_key: &key::PublicKey,
    // ) -> Result<Auth, Self::Error> {
    //     todo!()
    //     // Ok(Auth::Accept)
    // }

    // #[allow(unused_variables)]
    // async fn auth_publickey(
    //     &mut self,
    //     user: &str,
    //     public_key: &key::PublicKey,
    // ) -> Result<Auth, Self::Error> {
    //     todo!("3");
    // }

    // #[allow(unused_variables)]
    // async fn auth_keyboard_interactive(
    //     &mut self,
    //     user: &str,
    //     submethods: &str,
    //     response: Option<Response<'async_trait>>,
    // ) -> Result<Auth, Self::Error> {
    //     todo!("4");
    // }

    // /// Called when authentication succeeds for a session.
    // #[allow(unused_variables)]
    // async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
    //     todo!("5");
    // }
}
