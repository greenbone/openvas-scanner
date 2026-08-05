//! `mTLS` [`Acceptor`](MtlsAcceptor) and [`Service`](MtlsService).
//!
//! Various parts required to communicate information about the `mTLS` handshake into the
//! application layer of axum.
use axum::http::{self, Request};
use axum_server::{
    accept::{Accept, DefaultAcceptor},
    tls_rustls::RustlsAcceptor,
};
use rustls::{
    pki_types::{CertificateDer, pem::PemObject},
    server::danger::ClientCertVerifier,
};
use sha2::{Digest, Sha256};
use std::{fmt::Display, fs, io, path::Path, pin::Pin, sync::Arc, task};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Service;

/// Sha256 hash for the clients `mTLS` certificate.
#[derive(Clone, Debug)]
pub struct MtlsCertHash(Option<[u8; 32]>);

impl Display for MtlsCertHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(hash) => f.write_str(&hash.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            None => f.write_str("unknown"),
        }
    }
}

/// Wrapper around the default [`RustlsAcceptor`].
///
/// Extracts the clients `mTLS` peer certificate and injects a sha256 hash of it back into the
/// axum extensions via the [`MtlsService`].
#[derive(Clone)]
pub struct MtlsAcceptor<A = DefaultAcceptor> {
    inner: RustlsAcceptor<A>,
}

impl<A> MtlsAcceptor<A> {
    pub fn new(inner: RustlsAcceptor<A>) -> MtlsAcceptor<A> {
        Self { inner }
    }

    pub fn inner(&self) -> &RustlsAcceptor<A> {
        &self.inner
    }

    /// Hashes a given peer certificate
    fn hash(cert: &CertificateDer) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(cert);
        hasher.finalize().into()
    }
}

impl<I, S, A> Accept<I, S> for MtlsAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: Send,
    A::Future: Send,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<A::Stream>;
    type Service = MtlsService<A::Service>;

    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner().clone();

        Box::pin(async move {
            // call the default RustlsAcceptor which also performs the mTLS handshake
            let (stream, service) = inner.accept(stream, service).await?;

            // hash the clients peer certificate if one was given
            let hash = MtlsCertHash(
                stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first().map(Self::hash)),
            );

            // pass the hash to the MtlsService which injects it into the axum extensions
            Ok((stream, MtlsService::new(service, hash)))
        })
    }
}

/// Simple [`Service`] that injects the clients peer certificate hash into the axum extensions
/// exposing it for the [`AuthService`](super::auth::AuthService).
#[derive(Clone)]
pub struct MtlsService<S> {
    inner: S,
    // sha256 hash of a clients valid mTLS peer certificate if provided
    cert_hash: MtlsCertHash,
}

impl<S> MtlsService<S> {
    /// Creates a new MtlsService called by [`MtlsAcceptor`]
    fn new(inner: S, cert_hash: MtlsCertHash) -> MtlsService<S> {
        MtlsService { inner, cert_hash }
    }
}

impl<S, B> Service<Request<B>> for MtlsService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, ctx: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(ctx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        if self.cert_hash.0.is_some() {
            tracing::debug!("client cert: {}", self.cert_hash);
        }

        // insert the client hash
        // used by the AuthService
        req.extensions_mut().insert(self.cert_hash.clone());
        self.inner.call(req)
    }
}

pub fn create_verifier(client_certs_path: &Path) -> anyhow::Result<Arc<dyn ClientCertVerifier>> {
    // Enable mTLS client authentication
    let mut roots = rustls::RootCertStore::empty();

    // Depending on how the client certificate has been created the directory has to
    // contain either the used intermediary CA certificate or the client certificates.
    let dir = fs::read_dir(client_certs_path)?;
    for cert_file in dir.filter_map(|x| x.ok()) {
        if let Ok(certs) = CertificateDer::pem_file_iter(cert_file.path()) {
            roots.add_parsable_certificates(certs.collect::<Result<Vec<_>, _>>()?);
        }
    }

    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        // Allow connections without client certificates.
        // This pushes the authentication to the AuthService.
        .allow_unauthenticated()
        .build()
        .map_err(|e| e.into())
}
