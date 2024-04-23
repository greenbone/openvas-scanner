// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

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

use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{read_one, Item};

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use std::{fs, io};

use crate::controller::ClientIdentifier;

#[derive(Debug)]
pub struct ClientSnitch {
    inner: Arc<dyn ClientCertVerifier>,
    pub client_identifier: Arc<RwLock<ClientIdentifier>>,
}

impl ClientSnitch {
    /// Construct a new `AllowAnyAnonymousOrAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(
        inner: Arc<dyn ClientCertVerifier>,
        client_identifier: Arc<RwLock<ClientIdentifier>>,
    ) -> Self {
        Self {
            inner,
            client_identifier,
        }
    }

    /// Wrap this verifier in an [`Arc`] and coerce it to `dyn ClientCertVerifier`
    #[inline(always)]
    pub fn boxed(self) -> Arc<dyn ClientCertVerifier> {
        // This function is needed to keep it functioning like the original verifier.
        Arc::new(self)
    }
}

impl ClientCertVerifier for ClientSnitch {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let result = self
            .inner
            .verify_client_cert(end_entity, intermediates, now);
        if result.is_ok() {
            let mut ci = self.client_identifier.write().unwrap();
            *ci = ClientIdentifier::Known(end_entity.into());
        }
        result
    }
}
/// Data required to create a TlsConfig
type Error = Box<dyn std::error::Error + Send + Sync>;

pub fn config_to_tls_paths(
    config: &crate::config::Config,
) -> Result<Option<(PathBuf, PathBuf, Vec<PathBuf>)>, Error> {
    let key_path = match &config.tls.key {
        Some(x) => x,
        None => return Ok(None),
    };
    let certs = match &config.tls.certs {
        Some(x) => x,
        None => return Ok(None),
    };
    //   .expect("When a tls.key is set, a certificate must be set as well");
    let client_certs = match &config.tls.client_certs {
        Some(x) => x,
        None => {
            return Ok(Some((key_path.to_path_buf(), certs.to_path_buf(), vec![])));
        }
    };
    let client_certs = match std::fs::read_dir(client_certs) {
        Ok(x) => x,
        Err(_) => {
            return Ok(Some((key_path.to_path_buf(), certs.to_path_buf(), vec![])));
        }
    };
    let client_certs = client_certs
        .filter_map(|x| {
            let entry = x.ok()?;
            let file_type = entry.file_type().ok()?;
            if file_type.is_file() || file_type.is_symlink() && !file_type.is_dir() {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    Ok(Some((
        key_path.to_path_buf(),
        certs.to_path_buf(),
        client_certs,
    )))
}

pub type TlsData = (Arc<RwLock<ClientIdentifier>>, ServerConfig, bool);

pub fn tls_config(config: &crate::config::Config) -> Result<Option<TlsData>, Error> {
    let (key, certs, clients) = match config_to_tls_paths(config)? {
        Some(x) => x,
        None => return Ok(None),
    };

    let mut roots = RootCertStore::empty();
    for root in clients.iter().flat_map(load_certs).flatten() {
        roots.add(root)?;
    }
    let key = load_private_key(&key)?;
    let certs = load_certs(&certs)?;

    if !roots.is_empty() {
        let inner = WebPkiClientVerifier::builder(roots.into()).build()?;
        let client_identifier = Arc::new(RwLock::new(ClientIdentifier::default()));
        let verifier = ClientSnitch::new(inner, client_identifier.clone()).boxed();

        let mut config: ServerConfig = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?;

        config.alpn_protocols = vec![b"h2".to_vec()];

        Ok(Some((client_identifier, config, !clients.is_empty())))
    } else {
        match &config.tls.client_certs {
            Some(clicerts) => {
                match std::fs::read_dir(clicerts) {
                    Ok(_) => {
                        tracing::warn!(
                            client_certs = ?clicerts,
                            "No valid client certificates found"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            client_certs = ?clicerts,
                            error = ?e,
                            "Unable to load client certificates, continuing without them"
                        );
                    }
                };
            }
            None => {
                tracing::info!("Client verification disabled");
            }
        };
        let client_identifier = Arc::new(RwLock::new(ClientIdentifier::default()));
        let mut config: ServerConfig = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        config.alpn_protocols = vec![b"h2".to_vec()];

        Ok(Some((client_identifier, config, !clients.is_empty())))
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

// Load public certificate from file.
fn load_certs<P>(filename: &P) -> io::Result<Vec<CertificateDer<'static>>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).map(|x| x.into_iter().map(CertificateDer::from).collect())
}

// Load private key from file.
fn load_private_key<P>(filename: &P) -> io::Result<PrivateKeyDer<'static>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    loop {
        match read_one(&mut reader)? {
            None => break,
            Some(Item::RSAKey(key)) => {
                return Ok(PrivateKeyDer::from(PrivatePkcs1KeyDer::from(key)));
            }
            Some(Item::PKCS8Key(key)) => {
                return Ok(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)));
            }
            Some(Item::ECKey(key)) => return Ok(PrivateKeyDer::from(PrivateSec1KeyDer::from(key))),
            _ => {}
        }
    }
    Err(error(format!("No key found {filename:?}")))
}
