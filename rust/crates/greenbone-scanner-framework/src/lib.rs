use std::{
    marker::PhantomData,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use delete_scans_id::{DeleteScansID, DeleteScansIDIncomingRequest};
pub use entry::ClientHash;
pub use entry::ClientIdentifier;
pub use entry::IncomingRequest;
pub use entry::OnRequest;

use entry::Prefixed;
use get_scans::GetScansIncomingRequest;
use get_scans_id::GetScansIDIncomingRequest;
use get_scans_id_results::GetScansIDResultsIncomingRequest;
use get_scans_id_results_id::GetScansIDResultsIDIncomingRequest;
use get_scans_id_status::GetScansIDStatusIncomingRequest;
use get_scans_preferences::GetScansPreferencesIncomingRequest;
use get_vts::GetVTsIncomingRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};

pub mod delete_scans_id;
pub mod entry;
pub use entry::response::StreamResult;
mod get_scans;
pub use get_scans::GetScans;
pub use get_scans::GetScansError;
//TODO: move
mod get_scans_id;
pub use get_scans_id::{GetScansID, GetScansIDError};
mod get_scans_id_results;
pub use get_scans_id_results::{GetScansIDResults, GetScansIDResultsError};
mod get_scans_id_results_id;
pub use get_scans_id_results_id::{GetScansIDResultsID, GetScansIDResultsIDError};
mod get_scans_id_status;
pub use get_scans_id_status::{GetScansIDStatus, GetScansIDStatusError};
mod get_scans_preferences;
pub use get_scans_preferences::GetScansPreferences;
mod get_vts;
pub use get_vts::{GetVTsError, GetVts};
mod get_health;
pub use get_health::{GetHealthAlive, GetHealthAliveIncomingRequest};
pub use get_health::{GetHealthReady, GetHealthReadyIncomingRequest};
pub use get_health::{GetHealthStarted, GetHealthStartedIncomingRequest};

pub mod models;
mod post_scans;
use models::FeedState;
pub use post_scans::PostScans;
pub use post_scans::PostScansError;
pub mod post_scans_id;
mod tls;
pub use hyper::StatusCode;
use post_scans::PostScansIncomingRequest;
use post_scans_id::{PostScansID, PostScansIDIncomingRequest};
use tokio::net::TcpListener;

pub trait ExternalError: core::error::Error + Send + Sync + 'static {}

impl<T> ExternalError for T where T: core::error::Error + Send + Sync + 'static {}

pub mod prelude {
    //! Contains all use statements thate are exported within this framework.
    //!
    //! To use it call `use greenbone_scanner_framework::preluse::*`.

    pub use std::pin::Pin;

    pub use crate::{
        ClientHash, GetScans, GetScansError, GetScansID, GetScansIDError, GetScansIDResults,
        GetScansIDResultsError, GetScansIDResultsID, GetScansIDResultsIDError, GetScansIDStatus,
        GetScansIDStatusError, MapScanID, PostScans, PostScansError, StreamResult,
        delete_scans_id::{DeleteScansID, DeleteScansIDError},
        models,
        post_scans_id::PostScansID,
        post_scans_id::PostScansIDError,
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
pub struct TLSConfig {
    server_tls_cer: ServerCertificate,
    path_client_certs: Option<PathBuf>,
}

mod runtime_builder_states {
    pub struct Start;
    pub struct PostScansSet;
    pub struct GetScansSet;
    pub struct GetScanIDSet;
    pub struct GetScanIDResultSet;
    pub struct GetScanIDResultIDSet;
    pub struct GetScanIDStatusSet;
    pub struct PostScanIDSet;
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
// Additionall endpoints that are not scanner specific can be registered as well.
pub struct RuntimeBuilder<T> {
    // Contains the currently supported API versions.
    api_version: Vec<String>,
    feed_state: Option<Arc<RwLock<FeedState>>>,
    listener_address: SocketAddr,
    tls: Option<TLSConfig>,
    api_keys: Option<Vec<String>>,
    incoming_request: IncomingRequest,
    _phanton: PhantomData<T>,
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
        Self::new()
    }
}

impl<T> RuntimeBuilder<T> {
    pub fn new() -> RuntimeBuilder<runtime_builder_states::Start> {
        let mut incoming_request = IncomingRequest::with_capacity(13);
        incoming_request.push(GetScansPreferencesIncomingRequest::default());
        incoming_request.push(GetHealthAliveIncomingRequest::default());
        incoming_request.push(GetHealthReadyIncomingRequest::default());
        incoming_request.push(GetHealthStartedIncomingRequest::default());

        RuntimeBuilder {
            api_version: vec!["1".to_owned()],
            feed_state: None,
            tls: None,
            api_keys: None,
            incoming_request,
            listener_address: ([127, 0, 0, 1], 3000).into(),
            _phanton: PhantomData,
        }
    }

    pub fn feed_version(mut self, feed_state: Arc<RwLock<FeedState>>) -> RuntimeBuilder<T> {
        self.feed_state = Some(feed_state);
        self
    }

    pub fn listener_address(mut self, listener_address: SocketAddr) -> RuntimeBuilder<T> {
        self.listener_address = listener_address;
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

    pub fn api_keys(mut self, api_key: &[String]) -> RuntimeBuilder<T> {
        self.api_keys = Some(api_key.to_vec());
        self
    }

    pub fn insert_on_request<R>(mut self, value: R) -> RuntimeBuilder<T>
    where
        R: OnRequest + Sync + Send + 'static,
    {
        let mut idx = None;
        for (i, or) in self.incoming_request.on_requests.iter().enumerate() {
            if or.prefix() == value.prefix()
                && or.on_method() == value.on_method()
                && or.on_parts() == value.on_parts()
            {
                idx = Some(i);
                break;
            }
        }
        let value = Arc::new(Box::new(value) as Box<dyn OnRequest + Send + Sync + 'static>);
        if let Some(idx) = idx {
            self.incoming_request.on_requests[idx] = value;
        } else {
            self.incoming_request.on_requests.push(value);
        }
        self
    }

    // TODO: find a better name
    pub fn insert_additional_scan_endpoints<S, V>(
        self,
        scans: Arc<S>,
        vts: Arc<V>,
    ) -> RuntimeBuilder<T>
    where
        S: PostScans
            + GetScans
            + GetScansID
            + GetScansIDResults
            + GetScansIDResultsID
            + GetScansIDStatus
            + PostScansID
            + DeleteScansID
            + 'static,
        V: GetVts + Prefixed + 'static,
    {
        let ior = self
            .insert_on_request(PostScansIncomingRequest::from(scans.clone()))
            .insert_on_request(GetScansIncomingRequest::from(scans.clone()))
            .insert_on_request(GetScansIDIncomingRequest::from(scans.clone()))
            .insert_on_request(GetScansIDResultsIncomingRequest::from(scans.clone()))
            .insert_on_request(GetScansIDStatusIncomingRequest::from(scans.clone()))
            .insert_on_request(PostScansIDIncomingRequest::from(scans.clone()))
            .insert_on_request(DeleteScansIDIncomingRequest::from(scans))
            .insert_on_request(GetVTsIncomingRequest::from(vts));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }

    //pub fn incoming_request(mut self, incoming_request: IncomingRequest) -> RunTimeBuilder {
    //    self.incoming_request = Some(Arc::new(incoming_request));
    //    self
    //}

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
            + GetScansID
            + GetScansIDResults
            + GetScansIDResultsID
            + GetScansIDStatus
            + PostScansID
            + DeleteScansID
            + 'static,
    {
        let ior = self
            .insert_on_request(PostScansIncomingRequest::from(value.clone()))
            .insert_on_request(GetScansIncomingRequest::from(value.clone()))
            .insert_on_request(GetScansIDIncomingRequest::from(value.clone()))
            .insert_on_request(GetScansIDResultsIncomingRequest::from(value.clone()))
            .insert_on_request(GetScansIDStatusIncomingRequest::from(value.clone()))
            .insert_on_request(PostScansIDIncomingRequest::from(value.clone()))
            .insert_on_request(DeleteScansIDIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::Start> {
    pub fn insert_post_scans<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::PostScansSet>
    where
        T: PostScans + Prefixed + 'static,
    {
        let ior = self.insert_on_request(PostScansIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}
impl RuntimeBuilder<runtime_builder_states::PostScansSet> {
    pub fn insert_get_scans<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::GetScansSet>
    where
        T: GetScans + Prefixed + 'static,
    {
        let ior = self.insert_on_request(GetScansIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::GetScansSet> {
    pub fn insert_get_scans_id<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::GetScanIDSet>
    where
        T: GetScansID + Prefixed + 'static,
    {
        let ior = self.insert_on_request(GetScansIDIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::GetScanIDSet> {
    pub fn insert_get_scans_id_results<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::GetScanIDResultSet>
    where
        T: GetScansIDResults + Prefixed + 'static,
    {
        let ior = self.insert_on_request(GetScansIDResultsIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::GetScanIDResultSet> {
    pub fn insert_get_scans_id_results_id<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::GetScanIDResultIDSet>
    where
        T: GetScansIDResultsID + Prefixed + 'static,
    {
        let ior = self.insert_on_request(GetScansIDResultsIDIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::GetScanIDResultIDSet> {
    pub fn insert_get_scans_id_status<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::GetScanIDStatusSet>
    where
        T: GetScansIDStatus + Prefixed + 'static,
    {
        let ior = self.insert_on_request(GetScansIDStatusIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::GetScanIDStatusSet> {
    pub fn insert_post_scans_id<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::PostScanIDSet>
    where
        T: PostScansID + Prefixed + 'static,
    {
        let ior = self.insert_on_request(PostScansIDIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::PostScanIDSet> {
    pub fn insert_delete_scans_id<T>(
        self,
        value: Arc<T>,
    ) -> RuntimeBuilder<runtime_builder_states::DeleteScanIDSet>
    where
        T: DeleteScansID + 'static,
    {
        let ior = self.insert_on_request(DeleteScansIDIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
        }
    }
}

impl RuntimeBuilder<runtime_builder_states::DeleteScanIDSet> {
    pub fn insert_get_vts<T>(self, value: Arc<T>) -> RuntimeBuilder<runtime_builder_states::End>
    where
        T: GetVts + Prefixed + 'static,
    {
        let ior = self.insert_on_request(GetVTsIncomingRequest::from(value));
        RuntimeBuilder {
            api_version: ior.api_version,
            feed_state: ior.feed_state,
            listener_address: ior.listener_address,
            tls: ior.tls,
            api_keys: ior.api_keys,
            incoming_request: ior.incoming_request,
            _phanton: PhantomData,
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
        let incoming_request = Arc::new(self.incoming_request);

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
                let incoming_request = incoming_request.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => tls_stream,
                        Err(err) => {
                            tracing::debug!("failed to perform tls handshake: {err:#}");
                            return;
                        }
                    };
                    let cci = retrieve_and_reset_client_identifier(identifier);
                    let service = entry::EntryPoint::new(ctx, Arc::new(cci), incoming_request);
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
                let incoming_request = incoming_request.clone();
                tokio::spawn(async move {
                    let cci = ClientIdentifier::Unknown;
                    let service = entry::EntryPoint::new(ctx, Arc::new(cci), incoming_request);
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
/// Rather than forcing the implemenation of a scan specific endpoint to check for themselves this
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
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<InternalIdentifier>> + Send + 'a>>;
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("Client certificates configured but none available")]
    NoClientCertificatesFound,
}
pub enum Authentication {
    Disabled,
    MTLS,
    ApiKey(Vec<String>),
}

impl Authentication {
    pub fn static_str(&self) -> &'static str {
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
    pub api_version: String,
    pub authentication: Authentication,
    pub feed_version: Arc<RwLock<FeedState>>,
}

#[cfg(test)]
mod tests {
    // TODO
}
