use std::borrow::Cow;
use std::time::Duration;
use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use client::Msg;
use russh::keys::*;
use russh::*;
use tokio::net::ToSocketAddrs;

use super::error::SshError;
use super::{Port, Socket};

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
    pub async fn new(
        ip_addr: IpAddr,
        port: Port,
        timeout: Option<Duration>,
        keytype: Option<&str>,
        csciphers: Option<&str>,
        scciphers: Option<&str>,
        socket: Option<Socket>,
    ) -> Result<Self, SshError> {
        let preferred = construct_preferred(keytype, csciphers, scciphers)?;
        let config = client::Config {
            inactivity_timeout: timeout,
            preferred,
            ..Default::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let session = client::connect(config, (ip_addr, port), sh)
            .await
            .map_err(|e| SshError::Connect(e))?;

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

/// Takes a comma separated string of algorithms
/// and turns it into a list of names that russh accepts.
/// Returns Err(...) if any given name is invalid.
fn make_named_list<'a, N: TryFrom<&'a str> + Clone>(
    s: &'a str,
    error_variant: fn(String) -> SshError,
) -> Result<Cow<'static, [N]>, SshError> {
    Ok(Cow::from(
        s.split(",")
            .map(|alg| N::try_from(alg).map_err(|_| error_variant(alg.to_string())))
            .collect::<Result<Vec<_>, SshError>>()?,
    ))
}

fn construct_preferred(
    keytype: Option<&str>,
    csciphers: Option<&str>,
    scciphers: Option<&str>,
) -> Result<Preferred, SshError> {
    let key = keytype
        .map(|keytype| make_named_list(keytype, SshError::InvalidKeytype))
        .transpose()?
        .unwrap_or(Preferred::DEFAULT.key);
    let csciphers = csciphers
        .map(|csciphers| make_named_list(csciphers, SshError::InvalidCipher))
        .transpose()?
        .unwrap_or(Preferred::DEFAULT.cipher);
    // TODO: figure out what to do with this
    let scciphers = scciphers
        .map(|scciphers| make_named_list(scciphers, SshError::InvalidCipher))
        .transpose()?
        .unwrap_or(Preferred::DEFAULT.cipher);
    Ok(Preferred {
        key,
        cipher: csciphers,
        ..Preferred::DEFAULT
    })
}
