// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use rustls::{
    RootCertStore, ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
};
use rustls_pemfile::{Item, read_one};

use crate::entry::ClientIdentifier;

#[derive(Debug)]
struct ClientSnitch {
    inner: Arc<dyn ClientCertVerifier>,
    client_identifier: Arc<RwLock<ClientIdentifier>>,
}

impl ClientSnitch {
    /// Construct a new `AllowAnyAnonymousOrAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    fn new(
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
    fn boxed(self) -> Arc<dyn ClientCertVerifier> {
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
type Error = Box<dyn std::error::Error + Send + Sync>;

fn config_to_tls_paths(
    config: &super::TLSConfig,
) -> Result<(PathBuf, PathBuf, Vec<PathBuf>), Error> {
    let key_path = &config.server_tls_cer.key;
    let certs = &config.server_tls_cer.certificate;
    let client_certs = match &config.path_client_certs {
        Some(x) => x,
        None => {
            return Ok((key_path.to_path_buf(), certs.to_path_buf(), vec![]));
        }
    };
    let client_certs = match std::fs::read_dir(client_certs) {
        Ok(x) => x,
        Err(_) => {
            return Ok((key_path.to_path_buf(), certs.to_path_buf(), vec![]));
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
    Ok((key_path.to_path_buf(), certs.to_path_buf(), client_certs))
}

#[derive(Debug)]
pub struct TlsConfig {
    pub client_identifier: Arc<RwLock<ClientIdentifier>>,
    pub config: ServerConfig,
}

pub fn tls_config(config: &super::TLSConfig) -> Result<TlsConfig, Error> {
    // Install default crypto provider if none is set
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    let (key, certs, clients) = config_to_tls_paths(config)?;

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

        Ok(TlsConfig {
            client_identifier,
            config,
        })
    } else {
        let client_identifier = Arc::new(RwLock::new(ClientIdentifier::default()));
        let mut config: ServerConfig = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        config.alpn_protocols = vec![b"h2".to_vec()];

        Ok(TlsConfig {
            client_identifier,
            config,
        })
    }
}

fn error(err: String) -> io::Error {
    io::Error::other(err)
}

// Load public certificate from file.
fn load_certs<P>(filename: &P) -> io::Result<Vec<CertificateDer<'static>>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open certificate file.
    let certfile =
        fs::File::open(filename).map_err(|e| error(format!("failed to open {filename:?}: {e}")))?;
    let mut reader = io::BufReader::new(certfile);
    CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| error(format!("{e}")))
}

// Load private key from file.
fn load_private_key<P>(filename: &P) -> io::Result<PrivateKeyDer<'static>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    // Open keyfile.
    let keyfile =
        fs::File::open(filename).map_err(|e| error(format!("failed to open {filename:?}: {e}")))?;
    let mut reader = io::BufReader::new(keyfile);

    loop {
        match read_one(&mut reader)? {
            None => break,
            Some(Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::from(key));
            }
            Some(Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::from(key));
            }
            Some(Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::from(key));
            }
            _ => {}
        }
    }
    Err(error(format!("No key found {filename:?}")))
}
