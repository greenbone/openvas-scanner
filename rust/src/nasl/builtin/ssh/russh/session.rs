use std::time::Duration;
use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use client::Msg;
use russh::keys::*;
use russh::*;
use tokio::net::ToSocketAddrs;

use super::Port;

// async fn main() -> Result<()> {
//     // Session is a wrapper around a russh client, defined down below
//     let mut ssh = Session::connect(
//         cli.private_key,
//         cli.username.unwrap_or("root".to_string()),
//         (cli.host, cli.port),
//     )
//     .await?;
//     info!("Connected");

//     let code = ssh
//         .call(
//             &cli.command
//                 .into_iter()
//                 .map(|x| shell_escape::escape(x.into())) // arguments are escaped manually since the SSH protocol doesn't support quoting
//                 .collect::<Vec<_>>()
//                 .join(" "),
//         )
//         .await?;

//     println!("Exitcode: {:?}", code);
//     ssh.close().await?;
//     Ok(())
// }

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct SshSession {
    session: client::Handle<Client>,
    channel: Option<Channel<Msg>>,
}

impl SshSession {
    pub async fn new<A: ToSocketAddrs>(addrs: A) -> Result<Self, russh::Error> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let session = client::connect(config, addrs, sh).await?;

        Ok(Self {
            session,
            channel: None,
        })
    }

    // pub async fn open_channel(&mut self) -> Result<(), russh::Error> {
    //     self.channel = Some(self.session.channel_open_session().await?);
    //     Ok(())
    // }

    // async fn call(&mut self, command: &str) -> Result<u32, russh::Error> {
    //     let mut channel = self.session.channel_open_session().await?;
    //     channel.exec(true, command).await?;

    //     let mut code = None;
    //     let mut stdout = tokio::io::stdout();

    //     loop {
    //         // There's an event available on the session channel
    //         let Some(msg) = channel.wait().await else {
    //             break;
    //         };
    //         match msg {
    //             // Write data to the terminal
    //             ChannelMsg::Data { ref data } => {
    //                 stdout.write_all(data).await?;
    //                 stdout.flush().await?;
    //             }
    //             // The command has returned an exit code
    //             ChannelMsg::ExitStatus { exit_status } => {
    //                 code = Some(exit_status);
    //                 // cannot leave the loop immediately, there might still be more data to receive
    //             }
    //             _ => {}
    //         }
    //     }
    //     Ok(code.expect("program did not exit cleanly"))
    // }

    // async fn close(&mut self) -> Result<(), russh::Error> {
    //     self.session
    //         .disconnect(Disconnect::ByApplication, "", "English")
    //         .await?;
    //     Ok(())
    // }
}

pub struct SessionConfig {
    pub port: Port,
    pub ip_addr: IpAddr,
}

impl SessionConfig {
    pub fn new(port: Port, ip_addr: IpAddr) -> Self {
        Self { port, ip_addr }
    }
}
