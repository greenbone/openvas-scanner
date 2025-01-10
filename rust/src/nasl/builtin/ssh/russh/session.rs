// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::borrow::Cow;
use std::time::Duration;
use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use client::{connect, DisconnectReason, Session};
use russh::keys::*;
use russh::*;
use tracing::{error, warn};

use crate::nasl::builtin::ssh::error::SshErrorKind;
use crate::nasl::builtin::ssh::Output;
use crate::nasl::utils::error::WithErrorInfo;
use crate::nasl::utils::function::bytes_to_str;

use super::super::error::SshError;
use super::{AuthMethods, Port, SessionId, Socket};

struct Client {}

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn channel_close(&mut self, _: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn data(&mut self, _: ChannelId, _: &[u8], _: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called when the server sent a disconnect message
    ///
    /// If reason is an Error, this function should re-return the error so the join can also evaluate it
    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            DisconnectReason::Error(e) => {
                match e {
                    russh::Error::Disconnect => {}
                    _ => {
                        error!("SSH session disconnected due to error: {}", e);
                    }
                }
                Err(e)
            }
        }
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct SshSession {
    id: SessionId,
    session: client::Handle<Client>,
}

impl SshSession {
    // The alternative to many arguments here is making
    // the fields public or creating some sort of builder struct
    // both of which feel like much worse alternatives.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        id: SessionId,
        ip_addr: IpAddr,
        port: Port,
        timeout: Option<Duration>,
        keytype: Vec<key::Name>,
        csciphers: Vec<cipher::Name>,
        scciphers: Vec<cipher::Name>,
        socket: Option<Socket>,
    ) -> Result<Self, SshError> {
        if socket.is_some() {
            error!("Using custom sockets not yet implemented.");
            return Err(SshErrorKind::Unimplemented.with(id));
        }
        let preferred = construct_preferred(keytype, csciphers, scciphers);
        let config = client::Config {
            inactivity_timeout: timeout,
            preferred,
            ..Default::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let session = connect(config, (ip_addr, port), sh)
            .await
            .map_err(|e| SshErrorKind::Connect.with(id).with(e))?;

        Ok(Self { session, id })
    }

    pub async fn exec_ssh_cmd(&self, command: &str) -> Result<Output, SshError> {
        let (stdout, stderr) = self.call(command).await.map_err(|e| {
            SshErrorKind::RequestExec(command.to_string())
                .with(self.id)
                .with(e)
        })?;
        Ok(Output { stdout, stderr })
    }

    pub async fn call(&self, command: &str) -> Result<(String, String), russh::Error> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut code = None;
        let mut stdout = String::new();
        let mut stderr = String::new();

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    stdout.push_str(&bytes_to_str(data));
                }
                ChannelMsg::ExtendedData { ref data, .. } => {
                    stderr.push_str(&bytes_to_str(data));
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                    channel.eof().await?;
                }
                _ => {}
            }
        }
        if code.is_none() {
            warn!("Program did not exit cleanly: {}", command);
        }
        Ok((stdout.to_string(), stderr.to_string()))
    }

    pub async fn auth_password(&mut self, login: &str, password: &str) -> Result<(), SshError> {
        self.session
            .authenticate_password(login, password)
            .await
            .map_err(|_| SshErrorKind::UserAuthPassword.with(self.id))
            .map(|_| ())
    }

    pub async fn auth_keyboard_interactive(
        &mut self,
        login: &str,
        password: &str,
    ) -> Result<(), SshError> {
        let make_err = || SshErrorKind::UserAuthKeyboardInteractive.with(self.id);
        let response = self
            .session
            .authenticate_keyboard_interactive_start(login, None)
            .await
            .map_err(|_| make_err())?;
        match response {
            client::KeyboardInteractiveAuthResponse::Success => Ok(()),
            client::KeyboardInteractiveAuthResponse::Failure => Err(make_err()),
            client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let mut answers: Vec<String> = Vec::new();
                for p in prompts.into_iter() {
                    if !p.echo {
                        answers.push(password.to_string());
                    } else {
                        answers.push(String::new());
                    };
                }
                self.session
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|_| make_err())
                    .map(|_| ())
            }
        }
    }

    pub async fn auth_method_allowed(&mut self, _method: AuthMethods) -> Result<bool, SshError> {
        // TODO: Actually check which auth methods are allowed.
        // Don't really know how to do this
        Ok(true)
    }
}

fn construct_preferred(
    keytype: Vec<key::Name>,
    csciphers: Vec<cipher::Name>,
    scciphers: Vec<cipher::Name>,
) -> Preferred {
    // Only keep the intersection of scciphers and csciphers.
    let ciphers = csciphers
        .into_iter()
        .filter(|cs| scciphers.iter().any(|sc| sc == cs))
        .collect::<Vec<_>>();
    Preferred {
        key: Cow::from(keytype),
        cipher: Cow::from(ciphers),
        ..Preferred::DEFAULT
    }
}
