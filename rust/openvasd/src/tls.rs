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
use rustls::server::{AllowAnyAuthenticatedClient, ClientCertVerifier};
use rustls::RootCertStore;
use rustls_pemfile::{read_one, Item};

use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use std::{fs, io};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::ServerConfig;

use crate::controller::{ClientGossiper, ClientIdentifier};

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
    pub client_identifier: Arc<RwLock<ClientIdentifier>>,
}

impl TlsStream {
    fn new(
        stream: AddrStream,

        roots: RootCertStore,
        certs: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
    ) -> TlsStream {
        let client_identifier = Arc::new(RwLock::new(ClientIdentifier::default()));
        let inner = AllowAnyAuthenticatedClient::new(roots);
        let verifier = ClientSnitch::new(inner, client_identifier.clone()).boxed();
        let config: Arc<ServerConfig> = Arc::new(server_config(verifier, certs, key).unwrap());

        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
            client_identifier,
        }
    }
}

impl ClientGossiper for TlsStream {
    fn client_identifier(
        &self,
    ) -> &std::sync::Arc<std::sync::RwLock<crate::controller::ClientIdentifier>> {
        &self.client_identifier
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
    roots: RootCertStore,
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(
        roots: RootCertStore,
        certs: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
        incoming: AddrIncoming,
    ) -> TlsAcceptor {
        TlsAcceptor {
            roots,
            certs,
            key,
            incoming,
        }
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
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(
                sock,
                pin.roots.clone(),
                pin.certs.clone(),
                pin.key.clone(),
            )))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

struct ClientSnitch {
    inner: AllowAnyAuthenticatedClient,
    client_identifier: Arc<RwLock<ClientIdentifier>>,
}

impl ClientSnitch {
    /// Construct a new `AllowAnyAnonymousOrAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(
        inner: AllowAnyAuthenticatedClient,
        client_identifier: Arc<RwLock<ClientIdentifier>>,
    ) -> Self {
        Self {
            inner,
            client_identifier,
        }
    }

    /// Update the verifier to validate client certificates against the provided DER format
    /// unparsed certificate revocation lists (CRLs).
    #[allow(dead_code)]
    pub fn with_crls(
        self,
        crls: impl IntoIterator<Item = rustls::server::UnparsedCertRevocationList>,
        client_identifier: Arc<RwLock<ClientIdentifier>>,
    ) -> Result<Self, rustls::CertRevocationListError> {
        // This function is needed to keep it functioning like the original verifier.
        Ok(Self {
            inner: self.inner.with_crls(crls)?,
            client_identifier,
        })
    }

    /// Wrap this verifier in an [`Arc`] and coerce it to `dyn ClientCertVerifier`
    #[inline(always)]
    pub fn boxed(self) -> Arc<dyn rustls::server::ClientCertVerifier> {
        // This function is needed to keep it functioning like the original verifier.
        Arc::new(self)
    }
}

impl rustls::server::ClientCertVerifier for ClientSnitch {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        match self
            .inner
            .verify_client_cert(end_entity, intermediates, now)
        {
            Ok(r) => {
                let mut ci = self.client_identifier.write().unwrap();
                *ci = ClientIdentifier::Known(end_entity.into());
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }
}
/// Data required to create a TlsConfig
type TlsData = (RootCertStore, Vec<rustls::Certificate>, rustls::PrivateKey);
/// Creates a root cert store, the certificates and a private key so that a tls configuration can be created.
///
/// When the tls certificate cannot be loaded it will return None.
/// When client certificates are provided it will return a ServerConfig with
/// client authentication otherwise it will return a ServerConfig without
/// client authentication.
pub fn tls_config(
    config: &crate::config::Config,
) -> Result<Option<TlsData>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(certs_path) = &config.tls.certs {
        match load_certs(certs_path) {
            Ok(certs) => {
                if let Some(key_path) = &config.tls.key {
                    let key = load_private_key(key_path)?;
                    let client_certs = if let Some(cpath) = &config.tls.client_certs {
                        let rd = std::fs::read_dir(cpath)?;
                        rd.filter_map(|entry| {
                            let entry = entry.ok()?;
                            let file_type = entry.file_type().ok()?;
                            if file_type.is_file() || file_type.is_symlink() && !file_type.is_dir()
                            {
                                Some(entry.path())
                            } else {
                                None
                            }
                        })
                        .collect()
                    } else {
                        vec![]
                    };
                    let mut roots = RootCertStore::empty();
                    for root in client_certs.iter().flat_map(load_certs).flatten() {
                        roots.add(&root)?;
                    }

                    Ok(Some((roots, certs, key)))
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

fn server_config(
    verifier: Arc<dyn ClientCertVerifier>,
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut cfg = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| error(format!("{}", e)))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(cfg)
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
