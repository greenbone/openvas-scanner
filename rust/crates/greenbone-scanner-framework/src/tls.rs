// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::HashSet,
    fs,
    io::{self, BufRead},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as RustlsError, RootCertStore, ServerConfig,
    SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use x509_parser::time::ASN1Time;

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
) -> Result<(PathBuf, PathBuf, Vec<PathBuf>, Vec<PathBuf>), Error> {
    let key_path = &config.server_tls_cer.key;
    let certs = &config.server_tls_cer.certificate;
    let client_certs = config
        .path_client_certs
        .as_deref()
        .map(load_client_cert_paths)
        .unwrap_or_default();
    let pinned_client_certs = config
        .path_pinned_client_certs
        .as_deref()
        .map(load_pinned_client_cert_paths)
        .transpose()
        .map_err(|e| error(format!("failed to load tls.pinned_client_certs: {e}")))?
        .unwrap_or_default();

    Ok((
        key_path.to_path_buf(),
        certs.to_path_buf(),
        client_certs,
        pinned_client_certs,
    ))
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

    let (key, certs, clients, pinned_clients) = config_to_tls_paths(config)?;

    let ca_certs = load_client_certs(&clients);
    let pinned_certs = load_pinned_client_certs(&pinned_clients)?;
    let client_cert_verifier = build_client_cert_verifier(ca_certs, pinned_certs)?;
    let key = load_private_key(&key)?;
    let certs = load_certs(&certs)?;

    if let Some(inner) = client_cert_verifier {
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

fn load_client_cert_paths(path: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(path) {
        Ok(entries) => entries
            .filter_map(|x| {
                let entry = x.ok()?;
                let metadata = entry.metadata().ok()?;
                if metadata.is_file() {
                    Some(entry.path())
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn load_pinned_client_cert_paths(path: &Path) -> io::Result<Vec<PathBuf>> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        error(format!(
            "failed to read client authentication certificate path {path:?}: {e}"
        ))
    })?;

    if metadata.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if !metadata.is_dir() {
        return Err(error(format!(
            "client authentication certificate path {path:?} is neither a file nor a directory"
        )));
    }

    let paths = std::fs::read_dir(path)
        .map_err(|e| {
            error(format!(
                "failed to read client authentication certificate directory {path:?}: {e}"
            ))
        })?
        .filter_map(|x| match x {
            Ok(entry) => {
                let entry_path = entry.path();
                match std::fs::metadata(&entry_path) {
                    Ok(metadata) if metadata.is_file() => Some(Ok(entry_path)),
                    Ok(_) => None,
                    Err(e) => Some(Err(error(format!(
                        "failed to read metadata for client authentication certificate path {entry_path:?}: {e}"
                    )))),
                }
            }
            Err(e) => Some(Err(error(format!(
                "failed to read entry from client authentication certificate directory {path:?}: {e}"
            )))),
        })
        .collect::<io::Result<Vec<_>>>()?;

    if paths.is_empty() {
        return Err(error(format!(
            "No client authentication certificate files found in {path:?}; mTLS would not authenticate clients"
        )));
    }

    Ok(paths)
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

fn load_pinned_client_certs(paths: &[PathBuf]) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs = paths
        .iter()
        .map(load_certs)
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    if !paths.is_empty() && certs.is_empty() {
        return Err(error(format!(
            "No client certificates found in {paths:?}; mTLS would not authenticate clients"
        )));
    }

    Ok(certs)
}

fn load_client_certs(paths: &[PathBuf]) -> Vec<CertificateDer<'static>> {
    paths.iter().flat_map(load_certs).flatten().collect()
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
        match rustls::pki_types::PrivateKeyDer::pem_slice_iter(reader.fill_buf()?).next() {
            Some(Ok(key)) => return Ok(key),
            Some(Err(_)) => {}
            None => break,
        }
    }

    Err(error(format!("No key found {filename:?}")))
}

fn unix_time_to_asn1_time(now: UnixTime) -> std::result::Result<ASN1Time, RustlsError> {
    let secs = i64::try_from(now.as_secs())
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    ASN1Time::from_timestamp(secs)
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))
}

fn validate_pinned_client_cert(
    end_entity: &CertificateDer<'_>,
    now: UnixTime,
) -> std::result::Result<(), RustlsError> {
    let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let now = unix_time_to_asn1_time(now)?;
    let validity = cert.validity();

    if now < validity.not_before {
        return Err(RustlsError::InvalidCertificate(
            rustls::CertificateError::NotValidYet,
        ));
    }
    if now > validity.not_after {
        return Err(RustlsError::InvalidCertificate(
            rustls::CertificateError::Expired,
        ));
    }

    if cert
        .basic_constraints()
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?
        .is_some_and(|extension| extension.value.ca)
    {
        return Err(RustlsError::InvalidCertificate(
            rustls::CertificateError::InvalidPurpose,
        ));
    }

    if cert
        .key_usage()
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?
        .is_some_and(|extension| !extension.value.digital_signature())
    {
        return Err(RustlsError::InvalidCertificate(
            rustls::CertificateError::InvalidPurpose,
        ));
    }

    if !cert
        .extended_key_usage()
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?
        .is_some_and(|extension| extension.value.client_auth)
    {
        return Err(RustlsError::InvalidCertificate(
            rustls::CertificateError::InvalidPurpose,
        ));
    }

    Ok(())
}

#[derive(Debug)]
struct PinnedClientCertVerifier {
    ca_verifier: Option<Arc<dyn ClientCertVerifier>>,
    signature_verifier: Arc<dyn ClientCertVerifier>,
    root_hint_subjects: Vec<DistinguishedName>,
    pinned_certs: HashSet<Vec<u8>>,
}

impl PinnedClientCertVerifier {
    fn new(
        ca_verifier: Option<Arc<dyn ClientCertVerifier>>,
        signature_verifier: Arc<dyn ClientCertVerifier>,
        pinned_certs: Vec<CertificateDer<'static>>,
    ) -> Self {
        let root_hint_subjects = ca_verifier
            .as_ref()
            .map(|verifier| verifier.root_hint_subjects().to_vec())
            .unwrap_or_default();

        Self {
            ca_verifier,
            signature_verifier,
            root_hint_subjects,
            pinned_certs: pinned_certs
                .into_iter()
                .map(|cert| cert.as_ref().to_vec())
                .collect(),
        }
    }
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, RustlsError> {
        if let Some(ca_verifier) = &self.ca_verifier {
            match ca_verifier.verify_client_cert(end_entity, intermediates, now) {
                Ok(verified) => return Ok(verified),
                Err(error) if !self.pinned_certs.contains(end_entity.as_ref()) => {
                    return Err(error);
                }
                Err(_) => {}
            }
        }

        if self.pinned_certs.contains(end_entity.as_ref()) {
            validate_pinned_client_cert(end_entity, now)?;
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

fn build_client_cert_verifier(
    ca_certs: Vec<CertificateDer<'static>>,
    pinned_certs: Vec<CertificateDer<'static>>,
) -> Result<Option<Arc<dyn ClientCertVerifier>>, Error> {
    if ca_certs.is_empty() && pinned_certs.is_empty() {
        return Ok(None);
    }

    let mut signature_roots = RootCertStore::empty();
    for cert in ca_certs.iter().chain(pinned_certs.iter()).cloned() {
        signature_roots.add(cert)?;
    }

    let signature_verifier = WebPkiClientVerifier::builder(signature_roots.into()).build()?;
    if pinned_certs.is_empty() {
        return Ok(Some(signature_verifier));
    }

    let ca_verifier = if ca_certs.is_empty() {
        None
    } else {
        let mut ca_roots = RootCertStore::empty();
        for cert in ca_certs {
            ca_roots.add(cert)?;
        }
        Some(WebPkiClientVerifier::builder(ca_roots.into()).build()?)
    };

    Ok(Some(Arc::new(PinnedClientCertVerifier::new(
        ca_verifier,
        signature_verifier,
        pinned_certs,
    ))))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use rustls::pki_types::pem::PemObject;

    use super::*;

    const VALID_CERT_TIME: u64 = 1781308800;

    fn ensure_crypto_provider() {
        if CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
    }

    fn cert(bytes: &'static [u8]) -> CertificateDer<'static> {
        CertificateDer::pem_slice_iter(bytes)
            .next()
            .unwrap()
            .unwrap()
    }

    fn ca_cert() -> CertificateDer<'static> {
        cert(include_bytes!("test-data/ca.pem"))
    }

    fn pinned_client_cert() -> CertificateDer<'static> {
        cert(include_bytes!("test-data/pinned-client.pem"))
    }

    fn other_client_cert() -> CertificateDer<'static> {
        cert(include_bytes!("test-data/other-client.pem"))
    }

    fn untrusted_pinned_client_cert() -> CertificateDer<'static> {
        cert(include_bytes!("test-data/untrusted-pinned-client.pem"))
    }

    fn no_client_auth_cert() -> CertificateDer<'static> {
        cert(include_bytes!("test-data/no-client-auth-client.pem"))
    }

    fn no_digital_signature_cert() -> CertificateDer<'static> {
        cert(include_bytes!("test-data/no-digital-signature-client.pem"))
    }

    fn untrusted_other_client_cert() -> CertificateDer<'static> {
        cert(include_bytes!("test-data/untrusted-other-client.pem"))
    }

    fn tls_config_with_client_certs(
        path_client_certs: Option<PathBuf>,
        path_pinned_client_certs: Option<PathBuf>,
    ) -> crate::TLSConfig {
        crate::TLSConfig {
            server_tls_cer: crate::ServerCertificate::default(),
            path_client_certs,
            path_pinned_client_certs,
        }
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "greenbone-scanner-framework-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn verify_client_cert(
        verifier: &dyn ClientCertVerifier,
        cert: &CertificateDer<'_>,
    ) -> std::result::Result<ClientCertVerified, RustlsError> {
        verify_client_cert_at(verifier, cert, VALID_CERT_TIME)
    }

    fn verify_client_cert_at(
        verifier: &dyn ClientCertVerifier,
        cert: &CertificateDer<'_>,
        seconds_since_epoch: u64,
    ) -> std::result::Result<ClientCertVerified, RustlsError> {
        verifier.verify_client_cert(
            cert,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(seconds_since_epoch)),
        )
    }

    #[test]
    fn config_to_tls_paths_preserves_missing_client_certs_behavior() {
        let config = tls_config_with_client_certs(
            Some(PathBuf::from("/nonexistent/openvas-scanner/client-certs")),
            None,
        );

        let (_, _, client_certs, pinned_client_certs) = config_to_tls_paths(&config).unwrap();
        assert!(client_certs.is_empty());
        assert!(pinned_client_certs.is_empty());
    }

    #[test]
    fn config_to_tls_paths_preserves_empty_client_certs_dir_behavior() {
        let client_certs_dir = temp_test_dir("empty-client-certs");
        let config = tls_config_with_client_certs(Some(client_certs_dir.clone()), None);

        let (_, _, client_certs, pinned_client_certs) = config_to_tls_paths(&config).unwrap();
        assert!(client_certs.is_empty());
        assert!(pinned_client_certs.is_empty());

        fs::remove_dir(client_certs_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn config_to_tls_paths_ignores_client_certs_symlinked_dirs() {
        let client_certs_dir = temp_test_dir("client-certs-symlink-dir");
        let ca_cert_path = client_certs_dir.join("ca.pem");
        let linked_dir_target = client_certs_dir.join("linked-dir-target");
        let linked_dir = client_certs_dir.join("linked-dir");
        let broken_link = client_certs_dir.join("broken-link.pem");

        fs::write(&ca_cert_path, include_bytes!("test-data/ca.pem")).unwrap();
        fs::create_dir(&linked_dir_target).unwrap();
        std::os::unix::fs::symlink(&linked_dir_target, &linked_dir).unwrap();
        std::os::unix::fs::symlink(client_certs_dir.join("missing.pem"), &broken_link).unwrap();

        let config = tls_config_with_client_certs(Some(client_certs_dir.clone()), None);
        let (_, _, client_certs, pinned_client_certs) = config_to_tls_paths(&config).unwrap();

        assert_eq!(client_certs, vec![ca_cert_path]);
        assert!(pinned_client_certs.is_empty());

        fs::remove_file(linked_dir).unwrap();
        fs::remove_file(broken_link).unwrap();
        fs::remove_dir_all(client_certs_dir).unwrap();
    }

    #[test]
    fn config_to_tls_paths_labels_pinned_client_certs_path_errors() {
        let config = tls_config_with_client_certs(
            None,
            Some(PathBuf::from(
                "/nonexistent/openvas-scanner/pinned-client-certs",
            )),
        );

        let err = config_to_tls_paths(&config).unwrap_err();
        assert!(err.to_string().contains("tls.pinned_client_certs"), "{err}");
    }

    #[test]
    fn config_to_tls_paths_rejects_empty_pinned_client_certs_dir() {
        let pinned_client_certs_dir = temp_test_dir("empty-pinned-client-certs");
        let config = tls_config_with_client_certs(None, Some(pinned_client_certs_dir.clone()));

        let err = config_to_tls_paths(&config).unwrap_err();
        assert!(err.to_string().contains("tls.pinned_client_certs"), "{err}");
        assert!(
            err.to_string()
                .contains("No client authentication certificate files found"),
            "{err}"
        );

        fs::remove_dir(pinned_client_certs_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn config_to_tls_paths_ignores_pinned_client_certs_symlinked_dirs() {
        let pinned_client_certs_dir = temp_test_dir("pinned-client-certs-symlink-dir");
        let pinned_cert_path = pinned_client_certs_dir.join("pinned-client.pem");
        let linked_dir_target = pinned_client_certs_dir.join("linked-dir-target");
        let linked_dir = pinned_client_certs_dir.join("linked-dir");

        fs::write(
            &pinned_cert_path,
            include_bytes!("test-data/pinned-client.pem"),
        )
        .unwrap();
        fs::create_dir(&linked_dir_target).unwrap();
        std::os::unix::fs::symlink(&linked_dir_target, &linked_dir).unwrap();

        let config = tls_config_with_client_certs(None, Some(pinned_client_certs_dir.clone()));
        let (_, _, _, pinned_client_certs) = config_to_tls_paths(&config).unwrap();

        assert_eq!(pinned_client_certs, vec![pinned_cert_path]);

        fs::remove_file(linked_dir).unwrap();
        fs::remove_dir_all(pinned_client_certs_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn config_to_tls_paths_labels_pinned_client_certs_metadata_errors() {
        let pinned_client_certs_dir = temp_test_dir("pinned-client-certs-broken-symlink");
        let pinned_cert_path = pinned_client_certs_dir.join("pinned-client.pem");
        let broken_link = pinned_client_certs_dir.join("broken-link.pem");

        fs::write(
            &pinned_cert_path,
            include_bytes!("test-data/pinned-client.pem"),
        )
        .unwrap();
        std::os::unix::fs::symlink(pinned_client_certs_dir.join("missing.pem"), &broken_link)
            .unwrap();

        let config = tls_config_with_client_certs(None, Some(pinned_client_certs_dir.clone()));
        let err = config_to_tls_paths(&config).unwrap_err();
        let err = err.to_string();

        assert!(err.contains("tls.pinned_client_certs"), "{err}");
        assert!(err.contains("failed to read metadata"), "{err}");
        assert!(
            err.contains(&broken_link.to_string_lossy().to_string()),
            "{err}"
        );

        fs::remove_file(broken_link).unwrap();
        fs::remove_dir_all(pinned_client_certs_dir).unwrap();
    }

    #[test]
    fn ca_client_verifier_accepts_ca_issued_client_cert() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![ca_cert()], vec![])
            .unwrap()
            .unwrap();

        assert!(verify_client_cert(verifier.as_ref(), &pinned_client_cert()).is_ok());
    }

    #[test]
    fn ca_and_pinned_client_verifier_accepts_ca_issued_client_cert() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![ca_cert()], vec![pinned_client_cert()])
            .unwrap()
            .unwrap();

        assert!(verify_client_cert(verifier.as_ref(), &pinned_client_cert()).is_ok());
        assert!(verify_client_cert(verifier.as_ref(), &other_client_cert()).is_ok());
    }

    #[test]
    fn pinned_client_verifier_accepts_exact_leaf_without_ca() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![pinned_client_cert()])
            .unwrap()
            .unwrap();

        assert!(verify_client_cert(verifier.as_ref(), &pinned_client_cert()).is_ok());
    }

    #[test]
    fn pinned_client_verifier_reports_client_auth_optional() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![pinned_client_cert()])
            .unwrap()
            .unwrap();

        assert!(!verifier.client_auth_mandatory());
    }

    #[test]
    fn pinned_client_verifier_rejects_unpinned_leaf() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![pinned_client_cert()])
            .unwrap()
            .unwrap();

        assert!(verify_client_cert(verifier.as_ref(), &other_client_cert()).is_err());
    }

    #[test]
    fn pinned_client_verifier_rejects_pinned_leaf_before_not_before() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![pinned_client_cert()])
            .unwrap()
            .unwrap();

        assert!(
            verify_client_cert_at(verifier.as_ref(), &pinned_client_cert(), 1781288257).is_err()
        );
    }

    #[test]
    fn pinned_client_verifier_rejects_pinned_leaf_after_not_after() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![pinned_client_cert()])
            .unwrap()
            .unwrap();

        assert!(
            verify_client_cert_at(verifier.as_ref(), &pinned_client_cert(), 2096648259).is_err()
        );
    }

    #[test]
    fn pinned_client_verifier_rejects_pinned_ca_certificate() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![ca_cert()])
            .unwrap()
            .unwrap();

        assert!(verify_client_cert(verifier.as_ref(), &ca_cert()).is_err());
    }

    #[test]
    fn pinned_client_verifier_rejects_pinned_leaf_without_client_auth_usage() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![no_client_auth_cert()])
            .unwrap()
            .unwrap();

        assert!(verify_client_cert(verifier.as_ref(), &no_client_auth_cert()).is_err());
    }

    #[test]
    fn pinned_client_verifier_rejects_pinned_leaf_without_digital_signature_usage() {
        ensure_crypto_provider();
        let verifier = build_client_cert_verifier(vec![], vec![no_digital_signature_cert()])
            .unwrap()
            .unwrap();

        assert!(
            verify_client_cert_at(verifier.as_ref(), &no_digital_signature_cert(), 1782000000)
                .is_err()
        );
    }

    #[test]
    fn ca_and_pinned_client_verifier_accepts_pinned_leaf_from_untrusted_ca() {
        ensure_crypto_provider();
        let verifier =
            build_client_cert_verifier(vec![ca_cert()], vec![untrusted_pinned_client_cert()])
                .unwrap()
                .unwrap();

        // The pinned leaf is accepted even though its issuing CA is not trusted.
        assert!(verify_client_cert(verifier.as_ref(), &untrusted_pinned_client_cert()).is_ok());
        // A different leaf from the same untrusted CA is rejected: pinning the
        // leaf does not extend trust to its issuer.
        assert!(verify_client_cert(verifier.as_ref(), &untrusted_other_client_cert()).is_err());
        // Clients issued by the configured CA keep working.
        assert!(verify_client_cert(verifier.as_ref(), &other_client_cert()).is_ok());
    }
}
