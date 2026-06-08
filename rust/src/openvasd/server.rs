use std::{
    fs,
    io::{self, BufRead},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::framework::{ClientHash, ClientIdentifier};
use axum::{
    Extension,
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    serve as axum_serve,
};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use futures::future::BoxFuture;
use rustls::{
    RootCertStore, ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
};
use tokio_rustls::server::TlsStream;
use tower::Layer;

use crate::{
    app::{AppState, HealthHeaders},
    config::Config,
    notus::NotusEndpoints,
    scans::Scans,
};

#[derive(Clone)]
struct ApiKeyIdentifier {
    configured_api_key: Option<String>,
}

impl ApiKeyIdentifier {
    fn new(app_state: &AppState<'_>) -> Self {
        Self {
            configured_api_key: app_state.config.endpoints.key.clone(),
        }
    }

    fn ident_from_api_key(&self, api_key: Option<&HeaderValue>) -> ClientIdentifier {
        match (self.configured_api_key.as_deref(), api_key) {
            (Some(expected), Some(provided)) if provided.as_bytes() == expected.as_bytes() => {
                ClientIdentifier::Known(ClientHash::from(provided.as_bytes()))
            }
            (Some(_), Some(_)) | (Some(_), None) => ClientIdentifier::Unknown,
            (None, Some(provided)) => {
                ClientIdentifier::Known(ClientHash::from(provided.as_bytes()))
            }
            (None, None) => ClientIdentifier::Known(ClientHash::from("dummyuser")),
        }
    }
}

async fn request_middleware(
    mut request: Request,
    next: Next,
    headers: HealthHeaders,
    request_guard: Arc<Semaphore>,
    api_key_identifier: Option<ApiKeyIdentifier>,
) -> Response {
    let Ok(permit) = request_guard.try_acquire_owned() else {
        let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
        headers.apply_to_response(&mut response);
        return response;
    };

    if let Some(api_key_identifier) = api_key_identifier {
        let ident = api_key_identifier.ident_from_api_key(request.headers().get("X-API-KEY"));
        request.extensions_mut().insert(ident);
    }

    // FIXME: This semaphore only covers request handling until the `Response` is
    // created. For streaming endpoints, response-body production continues after
    // `next.run(request).await` returns, so the permit is released too early.
    // That means this still helps against bursts of new requests, but it does
    // not fully protect long-lived streams (for example `/scans/{id}/results`
    // or `/vts`) or backend work that continues while the body is sent. Fixing
    // that would require holding the permit for the full response-body lifetime,
    // which does not seem worth it for now.
    let mut response = next.run(request).await;
    drop(permit);
    headers.apply_to_response(&mut response);
    response
}

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
enum TlsSetup {
    Plain(RustlsConfig),
    Mtls(MtlsSnitchAcceptor),
}

#[derive(Debug, Clone)]
struct MtlsSnitchAcceptor {
    inner: RustlsAcceptor,
}

impl MtlsSnitchAcceptor {
    fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for MtlsSnitchAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = axum::middleware::AddExtension<S, ClientIdentifier>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();

        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let ident = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| ClientIdentifier::Known(cert.as_ref().into()))
                .unwrap_or(ClientIdentifier::Unknown);
            let service = Extension(ident).layer(service);
            Ok((stream, service))
        })
    }
}

async fn shutdown_signal() {
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigquit = signal(SignalKind::quit()).expect("install SIGQUIT handler");
    let mut sighup = signal(SignalKind::hangup()).expect("install SIGHUP handler");

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Exit based on SIGTERM signal.");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("Exit based on SIGINT signal.");
                break;
            }
            _ = sigquit.recv() => {
                tracing::info!("Exit based on SIGQUIT signal.");
                break;
            }
            _ = sighup.recv() => {
                tracing::info!("Ignoring SIGHUP signal.");
            }
        }
    }
}

fn error(err: String) -> io::Error {
    io::Error::other(err)
}

fn load_certs<P>(filename: &P) -> io::Result<Vec<CertificateDer<'static>>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    let certfile =
        fs::File::open(filename).map_err(|e| error(format!("failed to open {filename:?}: {e}")))?;
    let mut reader = io::BufReader::new(certfile);
    CertificateDer::pem_reader_iter(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| error(format!("{e}")))
}

fn load_private_key<P>(filename: &P) -> io::Result<PrivateKeyDer<'static>>
where
    P: AsRef<Path> + std::fmt::Debug,
{
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

fn load_client_cert_paths(path: &Path) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(path) {
        Ok(x) => x,
        Err(_) => return vec![],
    };

    entries
        .filter_map(|x| {
            let entry = x.ok()?;
            let file_type = entry.file_type().ok()?;
            if file_type.is_file() || file_type.is_symlink() && !file_type.is_dir() {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect()
}

fn rustls_config(config: &Config) -> Result<Option<TlsSetup>> {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    let (Some(cert_path), Some(key_path)) = (config.tls.certs.as_ref(), config.tls.key.as_ref())
    else {
        return Ok(None);
    };

    let mut roots = RootCertStore::empty();
    if let Some(client_certs) = config.tls.client_certs.as_ref() {
        for root in load_client_cert_paths(client_certs)
            .iter()
            .flat_map(load_certs)
            .flatten()
        {
            roots.add(root)?;
        }
    }

    let key = load_private_key(key_path)?;
    let certs = load_certs(cert_path)?;

    let mut server_config = if !roots.is_empty() {
        let verifier = WebPkiClientVerifier::builder(roots.into()).build()?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let rustls_config = RustlsConfig::from_config(Arc::new(server_config));
    if config.tls.client_certs.is_some() {
        Ok(Some(TlsSetup::Mtls(MtlsSnitchAcceptor::new(
            RustlsAcceptor::new(rustls_config),
        ))))
    } else {
        Ok(Some(TlsSetup::Plain(rustls_config)))
    }
}

pub async fn serve<'a>(app_state: &'a AppState<'a>) -> Result<i32> {
    let headers = HealthHeaders::from_appstate(app_state);
    let scans = Scans::from_appstate(app_state);
    let cis_scans: crate::container_image_scanner::endpoints::scans::Scans =
        crate::container_image_scanner::endpoints::scans::Scans::from_appstate(app_state);
    let notus = NotusEndpoints::from_appstate(app_state);
    let vts = crate::vts::Endpoints::from_appstate(app_state);
    let app = headers
        .router("")
        .merge(headers.router("/container-image-scanner"))
        .merge(vts.clone().router(""))
        .merge(vts.router("/container-image-scanner"))
        .merge(scans.router())
        .merge(cis_scans.router())
        .merge(notus.router());
    let listener_address = app_state.config.listener.address;
    let max_concurrent_requests = app_state.config.storage.max_http_connections();
    let request_guard = Arc::new(Semaphore::new(max_concurrent_requests));

    if let Some(tls_setup) = rustls_config(app_state.config)? {
        tracing::info!("listening on https://{}", listener_address);
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(None);
        });

        match tls_setup {
            TlsSetup::Plain(tls_config) => {
                let api_key_identifier = ApiKeyIdentifier::new(app_state);
                axum_server::Server::bind(listener_address)
                    .acceptor(RustlsAcceptor::new(tls_config))
                    .handle(handle)
                    .serve(
                        app.layer(middleware::from_fn({
                            let api_key_identifier = api_key_identifier.clone();
                            let headers = headers.clone();
                            let request_guard = request_guard.clone();
                            move |request: Request, next: Next| {
                                request_middleware(
                                    request,
                                    next,
                                    headers.clone(),
                                    request_guard.clone(),
                                    Some(api_key_identifier.clone()),
                                )
                            }
                        }))
                        .into_make_service(),
                    )
                    .await?;
            }
            TlsSetup::Mtls(acceptor) => {
                axum_server::Server::bind(listener_address)
                    .acceptor(acceptor)
                    .handle(handle)
                    .serve(
                        app.layer(middleware::from_fn({
                            let headers = headers.clone();
                            let request_guard = request_guard.clone();
                            move |request: Request, next: Next| {
                                request_middleware(
                                    request,
                                    next,
                                    headers.clone(),
                                    request_guard.clone(),
                                    None,
                                )
                            }
                        }))
                        .into_make_service(),
                    )
                    .await?;
            }
        }
    } else {
        tracing::info!("listening on http://{}", listener_address);
        let listener = TcpListener::bind(listener_address).await?;
        let api_key_identifier = ApiKeyIdentifier::new(app_state);
        axum_serve(
            listener,
            app.layer(middleware::from_fn({
                let api_key_identifier = api_key_identifier.clone();
                let headers = headers.clone();
                let request_guard = request_guard.clone();
                move |request: Request, next: Next| {
                    request_middleware(
                        request,
                        next,
                        headers.clone(),
                        request_guard.clone(),
                        Some(api_key_identifier.clone()),
                    )
                }
            }))
            .into_make_service(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    Ok(0)
}
