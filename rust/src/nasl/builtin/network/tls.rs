// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use core::fmt;
use std::{
    fmt::{Display, Formatter},
    fs,
    io::{self, BufReader},
    sync::Arc,
};

use pkcs8::der::Decode;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    version::{TLS12, TLS13},
};

use crate::nasl::builtin::http::NoVerifier;

use super::OpenvasEncaps;

pub enum TLSError {
    Io(io::Error),
    Rustls(rustls::Error),
    KeyError(String),
}

impl From<io::Error> for TLSError {
    fn from(err: io::Error) -> Self {
        TLSError::Io(err)
    }
}

impl From<rustls::Error> for TLSError {
    fn from(err: rustls::Error) -> Self {
        TLSError::Rustls(err)
    }
}

impl Display for TLSError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            TLSError::Io(err) => write!(f, "{err}"),
            TLSError::Rustls(err) => write!(f, "Rustls error: {err}"),
            TLSError::KeyError(err) => write!(f, "Key error: {err}"),
        }
    }
}

fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>, TLSError> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            None => break,
            _ => {}
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("No private key found in {filename}"),
    ))?
}

pub fn prepare_tls_client(
    cert_path: &str,
    key_path: &str,
    password: &str,
    cafile_path: &str,
    transport: &OpenvasEncaps,
) -> Result<ClientConfig, TLSError> {
    let config = match transport {
        OpenvasEncaps::Tls12 => ClientConfig::builder_with_protocol_versions(&[&TLS12]),
        OpenvasEncaps::Tls13 => ClientConfig::builder_with_protocol_versions(&[&TLS13]),
        _ => ClientConfig::builder(),
    };

    let config = if cafile_path.is_empty() {
        config
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
    } else {
        let mut root_store = RootCertStore::empty();
        let ca_file = fs::File::open(cafile_path)?;
        let mut reader = BufReader::new(ca_file);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).map(|result| result.unwrap()),
        );

        ClientConfig::builder().with_root_certificates(root_store)
    };

    let config = if !cert_path.is_empty() && !key_path.is_empty() {
        let cert_file = fs::File::open(cert_path)?;
        let mut reader = BufReader::new(cert_file);
        let cert = rustls_pemfile::certs(&mut reader)
            .map(|result| result.unwrap())
            .collect();

        let mut key = load_private_key(key_path)?;

        if !password.is_empty() {
            let encrypted_key = pkcs8::EncryptedPrivateKeyInfo::from_der(key.secret_der())
                .map_err(|e| TLSError::KeyError(format!("Failed to parse encrypted key: {e}")))?;
            let decrypted_key = encrypted_key.decrypt(password).map_err(|e| {
                TLSError::KeyError(format!("Failed to decrypt key with provided password: {e}"))
            })?;

            key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                decrypted_key.as_bytes().to_owned(),
            ));
        }
        config.with_client_auth_cert(cert, key).unwrap()
    } else {
        config.with_no_client_auth()
    };

    Ok(config)
}

pub fn create_tls_client(
    hostname: &str,
    cert_path: &str,
    key_path: &str,
    password: &str,
    cafile_path: &str,
    transport: &OpenvasEncaps,
) -> Result<ClientConnection, TLSError> {
    let server = ServerName::try_from(hostname.to_owned()).unwrap();
    let config = prepare_tls_client(cert_path, key_path, password, cafile_path, transport)?;
    ClientConnection::new(Arc::new(config), server).map_err(|e| e.into())
}
