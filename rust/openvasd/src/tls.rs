// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! TLS support for the openvasd.
//! To use it you need to provide a certificate and a key file.
//! If there are no client certificates provided, the server will start without
//! certificate based client authentication.
//!
//! ```rust
//!let scanner = scan::OSPDWrapper::from_env();
//!let ctx = controller::ContextBuilder::new()
//!    .scanner(scanner)
//!    .build();
//!let controller = std::sync::Arc::new(ctx);
//!let addr = ([127,0,0,1], 0).into();
//!let incoming = hyper::server::conn::AddrIncoming::bind(&addr)?;
//!let addr = incoming.local_addr();
//!
//!// when tls config is unable to load the certificates it will return None
//!// when client certificates are provided it will run in mtls.
//!if let Some(tlsc) = tls::tls_config(&config)? {
//!    let make_svc = crate::controller::make_svc!(&controller);
//!    let server = hyper::Server::builder(tls::TlsAcceptor::new(tlsc, incoming)).serve(make_svc);
//!    server.await?;
//!}
//!```
use core::task::{Context, Poll};
use futures_util::{ready, Future};
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use rustls::server::{AllowAnyAuthenticatedClient, NoClientAuth};
use rustls::RootCertStore;
use rustls_pemfile::{read_one, Item};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use std::{fs, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::ServerConfig;

enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

/// Holds the state of the tls connection
///
/// On the first read/write the connection will be handshaked and the state
/// will change to streaming.
///
/// On streaming the connection will be read/written.
pub struct TlsStream {
    state: State,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Handles the actual tls connection based on the given address and config.
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor { config, incoming }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

/// Creates a rustls ServerConfig based on the given config.
///
/// When the tls certificate cannot be loaded it will return None.
/// When client certificates are provided it will return a ServerConfig with
/// client authentication otherwise it will return a ServerConfig without
/// client authentication.
pub fn tls_config(
    config: &crate::config::Config,
) -> Result<Option<Arc<ServerConfig>>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(certs_path) = &config.tls.certs {
        match load_certs(certs_path) {
            Ok(certs) => {
                if let Some(key_path) = &config.tls.key {
                    let key = load_private_key(key_path)?;
                    let verifier = {
                        if let Some(client_certs_dir) = &config.tls.client_certs {
                            let client_certs: Vec<PathBuf> = std::fs::read_dir(client_certs_dir)?
                                .filter_map(|entry| {
                                    let entry = entry.ok()?;
                                    let file_type = entry.file_type().ok()?;
                                    if file_type.is_file()
                                        || file_type.is_symlink() && !file_type.is_dir()
                                    {
                                        Some(entry.path())
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            if client_certs.is_empty() {
                                tracing::info!(
                                    "no client certs found, starting without certificate based client auth"
                                );
                                NoClientAuth::boxed()
                            } else {
                                tracing::info!(
                                    "client certs found, starting with certificate based client auth"
                                );
                                let mut client_auth_roots = RootCertStore::empty();
                                for root in client_certs.iter().flat_map(load_certs).flatten() {
                                    client_auth_roots.add(&root)?;
                                }
                                AllowAnyAuthenticatedClient::new(client_auth_roots).boxed()
                            }
                        } else {
                            tracing::info!(
                                "no client certs found, starting without certificate based client auth"
                            );
                            NoClientAuth::boxed()
                        }
                    };

                    let mut cfg = rustls::ServerConfig::builder()
                        .with_safe_defaults()
                        //.with_client_cert_verifier()
                        .with_client_cert_verifier(verifier)
                        .with_single_cert(certs, key)
                        .map_err(|e| error(format!("{}", e)))?;
                    // Configure ALPN to accept HTTP/2, HTTP/1.1, and HTTP/1.0 in that order.
                    cfg.alpn_protocols =
                        vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
                    Ok(Some(std::sync::Arc::new(cfg)))
                } else {
                    Err(error("TLS enabled, but private key is missing".to_string()).into())
                }
            }
            Err(e) => Err(error(format!("failed to load TLS certificates: {}", e)).into()),
        }
    } else {
        tracing::info!("No Server certificates given, starting without TLS");
        Ok(None)
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
// Load public certificate from file.
fn load_certs<P>(filename: &P) -> io::Result<Vec<rustls::Certificate>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

// Load private key from file.
fn load_private_key<P>(filename: &P) -> io::Result<rustls::PrivateKey>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    let mut keys = Vec::<Vec<u8>>::new();
    loop {
        match read_one(&mut reader)? {
            None => break,
            Some(Item::RSAKey(key)) => keys.push(key),
            Some(Item::PKCS8Key(key)) => keys.push(key),
            Some(Item::ECKey(key)) => keys.push(key),
            _ => {}
        }
    }
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }

    Ok(rustls::PrivateKey(keys[0].clone()))
}
