use std::{
    marker::PhantomData,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, RwLock},
};

use delete_scans_id::{DeleteScansId, DeleteScansIdHandler};
use entry::Prefixed;
pub use entry::{ClientHash, ClientIdentifier, RequestHandler, RequestHandlers};
use get_scans::GetScansHandler;
use get_scans_id::GetScansIdHandler;
use get_scans_id_results::GetScansIdResultsHandler;
use get_scans_id_results_id::GetScansIdResultsIdHandler;
use get_scans_id_status::GetScansIdStatusHandler;
use get_scans_preferences::GetScansPreferencesHandler;
use get_vts::GetVTsHandler;
use hyper_util::rt::{TokioExecutor, TokioIo};

mod delete_scans_id;
pub mod entry;
pub use entry::response::StreamResult;
mod get_scans;
pub use get_scans::{GetScans, GetScansError};
//TODO: move
mod get_scans_id;
pub use get_scans_id::{GetScansIDError, GetScansId};
mod get_scans_id_results;
pub use get_scans_id_results::{GetScansIDResultsError, GetScansIdResults};
mod get_scans_id_results_id;
pub use get_scans_id_results_id::{GetScansIDResultsIDError, GetScansIdResultsId};
mod get_scans_id_status;
pub use get_scans_id_status::{GetScansIDStatusError, GetScansIdStatus};
mod get_scans_preferences;
pub use get_scans_preferences::GetScansPreferences;
mod get_vts;
pub use get_vts::{GetVTsError, GetVts};
mod get_health;
use get_health::{GetHealthAliveHandler, GetHealthReadyHandler, GetHealthStartedHandler};

pub mod models;
mod post_scans;
use models::FeedState;
pub use post_scans::{PostScans, PostScansError};
mod post_scans_id;
mod tls;
use post_scans::PostScansHandler;
use post_scans_id::{PostScansId, PostScansIdHandler};
use tokio::net::TcpListener;

pub trait ExternalError: core::error::Error + Send + Sync + 'static {}

impl<T> ExternalError for T where T: core::error::Error + Send + Sync + 'static {}

pub mod prelude {
    //! Contains all use statements thate are exported within this framework.
    //!
    //! To use it call `use greenbone_scanner_framework::preluse::*`.

    pub use crate::{
        ClientHash, GetScans, GetScansError, GetScansIDError, GetScansIDResultsError,
        GetScansIDResultsIDError, GetScansIDStatusError, GetScansId, GetScansIdResults,
        GetScansIdResultsId, GetScansIdStatus, GetScansPreferences, MapScanID, PostScans,
        PostScansError, StreamResult,
        delete_scans_id::{DeleteScansIDError, DeleteScansId},
        models,
        post_scans_id::{PostScansIDError, PostScansId},
    };
}

#[derive(Debug, Default)]
pub struct ServerCertificate {
    certificate: PathBuf,
    key: PathBuf,
}

impl ServerCertificate {
    pub fn new(key: PathBuf, cert: PathBuf) -> Self {
        Self {
            certificate: cert,
            key,
        }
    }
}

#[derive(Debug, Default)]
struct TLSConfig {
    server_tls_cer: ServerCertificate,
    path_client_certs: Option<PathBuf>,
}

mod runtime_builder_states {
    pub struct Start;
    pub struct DeleteScanIDSet;
    pub struct End;
}

// we hide all other states to not pollute the namespace too much
pub use runtime_builder_states::{End, Start};

// A scanner must have the endpoints:
// - POST /scans
// - GET /scans
// - POST /scans/{id}
// - GET /scans/{id}
// - DELETE /scans/{id}
// - GET /scans/{id}/status
// - GET /scans/{id}/results?range=n-n
// - GET /scans/{id}/results/{idx}
// - GET /vts
// Default available
// - GET /scans/preferences
// - GET /health/alive
// - GET /health/ready
// - GET /health/started
// Additionally, endpoints that are not scanner specific can be registered as well.
pub struct RuntimeBuilder<T> {
    // Contains the currently supported API versions.
    api_version: Vec<String>,
    feed_state: Option<Arc<RwLock<FeedState>>>,
    listener_address: SocketAddr,
    tls: Option<TLSConfig>,
    api_keys: Option<Vec<String>>,
    handlers: RequestHandlers,
    _phantom: PhantomData<T>,
}

fn retrieve_and_reset_client_identifier(id: Arc<RwLock<ClientIdentifier>>) -> ClientIdentifier {
    // get client information
    let mut ci = id.write().unwrap();
    let cci = ci.clone();
    // reset client information
    *ci = ClientIdentifier::Unknown;
    cci
}

impl Default for RuntimeBuilder<runtime_builder_states::Start> {
    fn default() -> Self {
        Self::new(([127, 0, 0, 1], 3000).into())
    }
}

impl<T> RuntimeBuilder<T> {
    pub fn new(listener_address: SocketAddr) -> RuntimeBuilder<runtime_builder_states::Start> {
        let mut handlers = RequestHandlers::default();
        //handlers.push(GetScansPreferencesHandler::default());
        // TODO: do per prefix?
        handlers.push(GetHealthAliveHandler::default());
        handlers.push(GetHealthReadyHandler::default());
        handlers.push(GetHealthStartedHandler::default());

        RuntimeBuilder {
            api_version: vec!["1".to_owned()],
            feed_state: None,
            tls: None,
            api_keys: None,
            handlers,
            listener_address,
            _phantom: PhantomData,
        }
    }

    pub fn feed_version(mut self, feed_state: Arc<RwLock<FeedState>>) -> RuntimeBuilder<T> {
        self.feed_state = Some(feed_state);
        self
    }

    pub fn server_tls_cer(mut self, server_tls_cer: ServerCertificate) -> RuntimeBuilder<T> {
        self.tls = Some(match self.tls {
            Some(TLSConfig {
                server_tls_cer: _,
                path_client_certs,
            }) => TLSConfig {
                server_tls_cer,
                path_client_certs,
            },
            None => TLSConfig {
                server_tls_cer,
                path_client_certs: None,
            },
        });

        self
    }

    pub fn path_client_certs(mut self, path_client_certs: PathBuf) -> RuntimeBuilder<T> {
        self.tls = Some(match self.tls {
            Some(TLSConfig {
                server_tls_cer,
                path_client_certs: _,
            }) => TLSConfig {
                server_tls_cer,
                path_client_certs: Some(path_client_certs),
            },
            None => TLSConfig {
                server_tls_cer: Default::default(),
                path_client_certs: Some(path_client_certs),
            },
        });
        self
    }

    pub fn add_request_handler<R>(mut self, value: R) -> RuntimeBuilder<T>
    where
        R: RequestHandler + Sync + Send + 'static,
    {
        let mut idx = None;
        for (i, or) in self.handlers.handlers.iter().enumerate() {
            if or.prefix() == value.prefix()
                && or.http_method() == value.http_method()
                && or.path_segments() == value.path_segments()
            {
                idx = Some(i);
                break;
            }
        }
        let value = Arc::new(Box::new(value) as Box<dyn RequestHandler + Send + Sync + 'static>);
        if let Some(idx) = idx {
            self.handlers.handlers[idx] = value;
        } else {
            self.handlers.handlers.push(value);
        }
        self
    }

    // TODO: find a better name add health endpoints
    pub fn insert_additional_scan_endpoints<S, V>(
        self,
        scans: Arc<S>,
        vts: Arc<V>,
    ) -> RuntimeBuilder<T>
    where
        S: PostScans
            + GetScans
            + GetScansPreferences
            + GetScansId
            + GetScansIdResults
            + GetScansIdResultsId
            + GetScansIdStatus
            + PostScansId
            + DeleteScansId
            + Prefixed
            + 'static,
        V: GetVts + Prefixed + 'static,
    {
        let ior = self
            .add_request_handler(PostScansHandler::from(scans.clone()))
            .add_request_handler(GetScansHandler::from(scans.clone()))
            .add_request_handler(GetScansPreferencesHandler::from(scans.clone()))
            .add_request_handler(GetScansIdHandler::from(scans.clone()))
            .add_request_handler(GetScansIdResultsHandler::from(scans.clone()))
            .add_request_handler(GetScansIdResultsIdHandler::from(scans.clone()))
            .add_request_handler(GetScansIdStatusHandler::from(scans.clone()))
            .add_request_handler(PostScansIdHandler::from(scans.clone()))
            .add_request_handler(DeleteScansIdHandler::from(scans))
            .add_request_handler(GetVTsHandler::from(vts));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            handlers: ior.handlers,
            _phantom: PhantomData,
        }
    }

    fn build_scanner(&self) -> Scanner {
        let authentication = match (&self.tls, &self.api_keys) {
            (
                Some(TLSConfig {
                    server_tls_cer: _,
                    path_client_certs: Some(_),
                }),
                None,
            ) => Authentication::MTLS,
            (
                Some(TLSConfig {
                    server_tls_cer: _,
                    path_client_certs: Some(_),
                }),
                Some(_),
            ) => {
                tracing::info!("mTLS and api-key configured, favoring mTLS and disabling api-key");
                Authentication::MTLS
            }
            (_, Some(_)) => Authentication::ApiKey(self.api_keys.clone().unwrap_or_default()),
            (_, None) => {
                tracing::warn!("neither api-key nor mTLS configured. Endpoints are not secured.");
                Authentication::Disabled
            }
        };
        Scanner {
            api_version: self.api_version.join(","),
            feed_version: self.feed_state.clone().unwrap_or_default(),
            authentication,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::Start> {
    pub fn insert_scans<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::DeleteScanIDSet>
    where
        T: PostScans
            + GetScans
            + GetScansPreferences
            + GetScansId
            + GetScansIdResults
            + GetScansIdResultsId
            + GetScansIdStatus
            + PostScansId
            + DeleteScansId
            + 'static,
    {
        let ior = self
            .add_request_handler(PostScansHandler::from(value.clone()))
            .add_request_handler(GetScansHandler::from(value.clone()))
            .add_request_handler(GetScansPreferencesHandler::from(value.clone()))
            .add_request_handler(GetScansIdHandler::from(value.clone()))
            .add_request_handler(GetScansIdResultsHandler::from(value.clone()))
            .add_request_handler(GetScansIdStatusHandler::from(value.clone()))
            .add_request_handler(PostScansIdHandler::from(value.clone()))
            .add_request_handler(DeleteScansIdHandler::from(value));

        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            handlers: ior.handlers,
            _phantom: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::DeleteScanIDSet> {
    pub fn insert_get_vts<T>(self, value: Arc<T>) -> RuntimeBuilder<runtime_builder_states::End>
    where
        T: GetVts + Prefixed + 'static,
    {
        let ior = self.add_request_handler(GetVTsHandler::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            handlers: ior.handlers,
            _phantom: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::End> {
    pub async fn run_blocking(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let scanner = Arc::new(self.build_scanner());
        let tls_config = match &self.tls {
            Some(x) => Some(tls::tls_config(x)?),
            None => None,
        };

        let incoming = TcpListener::bind(&self.listener_address).await?;
        let handlers = Arc::new(self.handlers);

        if let Some(tls_config) = tls_config {
            use hyper::server::conn::http2::Builder;
            tracing::info!("listening on https://{}", self.listener_address);

            let config = Arc::new(tls_config.config);
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(config);

            loop {
                let (tcp_stream, _remote_addr) = incoming.accept().await?;
                let tls_acceptor = tls_acceptor.clone();
                let identifier = tls_config.client_identifier.clone();
                let ctx = scanner.clone();
                let handlers = handlers.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => tls_stream,
                        Err(err) => {
                            tracing::debug!("failed to perform tls handshake: {err:#}");
                            return;
                        }
                    };
                    let cci = retrieve_and_reset_client_identifier(identifier);
                    let service = entry::EntryPoint::new(ctx, Arc::new(cci), handlers);
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls_stream), service)
                        .await
                    {
                        tracing::debug!("failed to serve connection: {err:#}");
                    }
                });
            }
        } else {
            use hyper::server::conn::http1::Builder;
            tracing::info!("listening on http://{}", self.listener_address);
            loop {
                let (tcp_stream, _remote_addr) = incoming.accept().await?;
                let ctx = scanner.clone();
                let handlers = handlers.clone();
                tokio::spawn(async move {
                    let cci = ClientIdentifier::Unknown;
                    let service = entry::EntryPoint::new(ctx, Arc::new(cci), handlers);
                    if let Err(err) = Builder::new()
                        .serve_connection(TokioIo::new(tcp_stream), service)
                        .await
                    {
                        tracing::debug!("failed to serve connection: {err:#}");
                    }
                });
            }
        }
    }
}

pub type InternalIdentifier = String;

/// This trait is used for scan id specific endpoints to return an internal identifier.
///
/// Rather than forcing the implementation of a scan specific endpoint to check for themselves this
/// trait is used. This not just makes the implementation easier but also allows us to get rid of
/// async requirements when e.b. building a stream.
///
/// Additionally it returns one id instead of two so that implementations don't need to be aware
/// about the client_identifier.
pub trait MapScanID: Send + Sync {
    /// Returns true when scan_id is available for the given client
    fn contains_scan_id<'a>(
        &'a self,
        client_id: &'a str,
        scan_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<InternalIdentifier>> + Send + 'a>>;
}

pub enum Authentication {
    Disabled,
    MTLS,
    ApiKey(Vec<String>),
}

impl Authentication {
    fn static_str(&self) -> &'static str {
        match self {
            Authentication::Disabled => "disabled",
            Authentication::MTLS => "mTLS",
            Authentication::ApiKey(_) => "api-key",
        }
    }
}

impl AsRef<str> for Authentication {
    fn as_ref(&self) -> &str {
        self.static_str()
    }
}

pub struct Scanner {
    api_version: String,
    authentication: Authentication,
    feed_version: Arc<RwLock<FeedState>>,
}
