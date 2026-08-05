//! Scanner HTTP REST API.
//!
//! This module contains all logic required to run an `axum` based HTTP API and communicate with the
//! `Scanner` and `Notus` to perform various scan operations.
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};

use axum_server::{
    Handle,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use libc::{SIGINT, SIGQUIT, SIGTERM};
use mtls::MtlsAcceptor;
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio::{
    signal,
    sync::{RwLock, oneshot},
};

pub mod response;
pub use response::StreamResult;
pub mod states;
pub use auth::Authentication;

mod auth;
pub mod error;
mod mtls;
mod router;
pub mod routes;

/// The current API version.
pub const API_VERSION: &str = "1";
pub type InternalIdentifier = String;

/// Main API configuration.
pub struct ApiConfig {
    /// Address to listen on.
    pub address: SocketAddr,
    /// Enabled authentication method, either `mTLS`, `api-key` or `disabled`.
    pub auth_method: Authentication,
    /// Server TLS certificate filepath.
    pub server_cert_path: Option<PathBuf>,
    /// Server TLS key filepath.
    pub server_key_file: Option<PathBuf>,
    /// Client mTLS certs or intermediary ca directory.
    pub client_certs_path: Option<PathBuf>,
    /// Max concurrent requests.
    pub max_requests: usize,
    /// List of valid api keys.
    pub api_keys: Arc<Vec<String>>,
    /// Feed database fetcher, redis or sqlite.
    pub feed: states::Feed,
    /// Scanner access point.
    pub scanner: states::ScannerBridge,
    /// Container image scanner access point.
    pub image_scanner: states::ScannerBridge,
    /// Notus products.
    pub notus: Arc<RwLock<scannerlib::notus::Notus>>,
    /// Enables the `GET /scans` and `GET /container-image-scanner` routes.
    pub enable_additional_routes: bool,
}

/// Main API entry point.
///
/// Configures the underlying TCP/TLS sockets and serves the REST API via [`axum`].
pub async fn run(cfg: &ApiConfig) -> anyhow::Result<i32> {
    // Spawns a task to listen for unix signals and perform graceful shutdowns
    let (signal_tx, mut signal_rx) = oneshot::channel::<i32>();
    let shutdown_handle = Handle::default();
    let handle = shutdown_handle.clone();
    tokio::spawn(async move {
        shutdown_signals(signal_tx).await;
        handle.graceful_shutdown(None);
    });

    let app = router::create_router(cfg);

    match (cfg.server_cert_path.as_ref(), cfg.server_key_file.as_ref()) {
        // Enable TLS if a certificate and key is present
        (Some(cert_path), Some(key_path)) => {
            let server_cert = CertificateDer::from_pem_file(cert_path)?;
            let server_key = PrivateKeyDer::from_pem_file(key_path)?;

            if CryptoProvider::get_default().is_none() {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            }

            let mut server_config = if let Some(client_certs_path) = cfg.client_certs_path.as_ref()
            {
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

                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    // Allow connections without client certificates.
                    // This pushes the authentication to the AuthService.
                    .allow_unauthenticated()
                    .build()?;

                rustls::ServerConfig::builder().with_client_cert_verifier(verifier)
            } else {
                // No mTLS
                rustls::ServerConfig::builder().with_no_client_auth()
            }
            .with_single_cert(vec![server_cert], server_key)?;

            // Enable HTTP2 negotiation
            server_config.alpn_protocols = vec![b"h2".to_vec()];

            let rustls_config = RustlsConfig::from_config(Arc::new(server_config));

            // Whether or not mTLS authentication is actually performed is configured in the
            // rustls_config earlier.
            let acceptor = MtlsAcceptor::new(RustlsAcceptor::new(rustls_config));

            tracing::info!("listening on https://{}", cfg.address);

            // Start with tls and HTTP2
            axum_server::bind(cfg.address)
                .acceptor(acceptor)
                .handle(shutdown_handle)
                .serve(app.into_make_service())
                .await?;
        }
        (None, None) => {
            tracing::info!("listening on http://{}", cfg.address);

            // Start without tls and HTTP1.1
            axum_server::bind(cfg.address)
                .handle(shutdown_handle)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            panic!("both a server cert and key file are required");
        }
    };

    println!("waiting for signal");

    // A non-error termination of axum_serve::serve can only be triggered by a signal
    signal_rx
        .try_recv()
        // Signal based linux exit codes are defined as 128 + signal number
        .map(|x| 128 + x)
        .map_err(|e| e.into())
}

/// Intercepts and processes shutdown signals.
///
/// Used in combination with a [`Handle`] to perform a graceful shutdown for the signals
/// `SIGINT`, `SIGTERM` and `SIGQUIT`.
///
/// A special case is `SIGHUP`, which is triggered when the controlling terminal is closed.
/// Instead of causing a shutdown as well it is being ignored forcing the scanner to keep running.
async fn shutdown_signals(tx: oneshot::Sender<i32>) {
    loop {
        let sigint = async {
            signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        let sigterm = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        let sigquit = async {
            signal::unix::signal(signal::unix::SignalKind::quit())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        let sighup = async {
            signal::unix::signal(signal::unix::SignalKind::hangup())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        let signal = tokio::select! {
            _ = sigint => {
                tracing::info!(signal=SIGINT, "Exit based on signal.");
                SIGINT
            },
            _ = sigterm => {
                tracing::info!(signal=SIGTERM, "Exit based on signal.");
                SIGTERM
            },
            _ = sigquit => {
                tracing::info!(signal=SIGQUIT, "Exit based on signal.");
                SIGQUIT
            },
            // Ignore sighup and keep running
            _ = sighup => {
                tracing::info!("Ignoring SIGHUP signal.");
                continue
            }
        };

        // Send the triggered signal back to the main thread to set the correct exit code
        tx.send(signal).expect("shutdown signal oneshot channel");

        break;
    }
}

#[cfg(test)]
pub(super) mod tests {
    use axum::{
        body::Body,
        http::{Request, header::*},
    };

    use std::fmt::Debug;

    use axum::response::Response;
    use tower::{Service, ServiceExt};

    pub async fn send_request<S>(router: &mut S, request: Request<Body>) -> Response<Body>
    where
        S: Service<Request<Body>, Response = Response<Body>>,
        S::Error: Debug,
    {
        router.ready().await.unwrap().call(request).await.unwrap()
    }

    pub fn json_request<T: serde::Serialize>(
        method: &str,
        uri: &str,
        payload: &T,
    ) -> Request<Body> {
        let body_bytes = serde_json::to_vec(payload).expect("Failed to serialize json payload");

        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(Body::from(body_bytes))
            .expect("valid HTTP request")
    }
}
