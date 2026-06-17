//! Entry contains every module struct which is considered and entry point
//!
//! An entry point handles each incoming request, it checks if an endpoint
//! requires client-id/api-key and adds all required header information for each
//! response.

use std::{
    convert::Infallible,
    fmt::Display,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
pub mod response;

use cidr::IpInet;
use hyper::{StatusCode, header::HeaderValue};
use response::{BodyKind, BodyKindContent};

#[derive(Clone, Default, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientHash([u8; 32]);

impl<T> From<T> for ClientHash
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(value);
        let hash = hasher.finalize();
        Self(hash.into())
    }
}

impl Display for ClientHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .fold(String::with_capacity(self.0.len() * 2), |mut a, x| {
                    a.push_str(&format!("{x:02x}"));
                    a
                })
        )
    }
}

/// Contains information about an authorization model of a connection (e.g. mtls)
#[derive(Default, Debug, Clone)]
pub enum ClientIdentifier {
    /// When there in no information available
    #[default]
    Unknown,
    /// Contains a hashed number of an identifier
    ///
    /// We uses the identifier as a key for results. This key is usually calculated by an
    /// subject of a known client certificate or by creating a sha256 sum of the used API key.
    Known(ClientHash),
}

// pub type Request<Body> = hyper::Request<Body>;
pub type Uri = hyper::Uri;
pub type Bytes = hyper::body::Bytes;
pub type Method = hyper::Method;

#[macro_export]
macro_rules! auth_method_segments {
    (authenticated: $authn:expr, $method:expr, $($path:literal),*) => {
        fn needs_authentication(
            &self,
        ) -> bool {
            $authn
        }

        fn path_segments(&self) -> &'static [&'static str] {
            &[ $( $path, )* ]
        }

        fn http_method(&self) -> $crate::entry::Method {
            $method
        }

    };
}

pub trait Prefixed {
    fn prefix(&self) -> &'static str;
}

pub trait RequestHandler: Prefixed {
    fn needs_authentication(&self) -> bool;
    fn path_segments(&self) -> &'static [&'static str];
    fn http_method(&self) -> Method;
    fn ids(&self, uri: &Uri) -> Vec<String> {
        if Self::prefix(self).is_empty() {
            uri.path()
                .split('/')
                .filter(|x| !x.is_empty())
                .zip(self.path_segments().iter())
                .filter(|(_, x)| x == &&"*")
                .map(move |(x, _)| x.to_owned())
                .collect()
        } else {
            uri.path()
                .split('/')
                .filter(|x| !x.is_empty())
                .skip(1)
                .zip(self.path_segments().iter())
                .filter(|(_, x)| x == &&"*")
                .map(move |(x, _)| x.to_owned())
                .collect()
        }
    }

    fn call<'a, 'b>(
        &'b self,
        client_id: Arc<ClientIdentifier>,
        uri: &'a Uri,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a;
}

#[derive(Clone, Debug, Default)]
pub struct EndpointPolicy {
    health_ip_allowlist: Vec<IpInet>,
    hide_declined_response_headers: bool,
}

impl EndpointPolicy {
    pub fn new(health_ip_allowlist: Vec<IpInet>) -> Self {
        Self {
            health_ip_allowlist,
            hide_declined_response_headers: false,
        }
    }

    pub fn hide_declined_response_headers(mut self, hide_declined_response_headers: bool) -> Self {
        self.hide_declined_response_headers = hide_declined_response_headers;
        self
    }

    fn allows_health_peer(&self, peer_addr: Option<SocketAddr>) -> bool {
        if self.health_ip_allowlist.is_empty() {
            return true;
        }

        peer_addr.is_some_and(|peer_addr| {
            let peer_ip = peer_addr.ip();
            self.health_ip_allowlist
                .iter()
                .any(|allowed| allowed.contains(&peer_ip))
        })
    }
}

/// Will be called after the authorization and sanity checks are done.
///
/// It contains all the RequestHandler implementations and finds handler
/// with matching path, method and authorization and calls it.
#[derive(Default, Clone)]
pub struct RequestHandlers {
    pub handlers: Vec<Arc<Box<dyn RequestHandler + Send + Sync>>>,
}

#[macro_export]
macro_rules! create_single_handler {
    ($($path:expr),*) => {{
        let mut ir = $crate::RequestHandlers::default();
        $(
            ir.push($path);
        )*
        ir


    }};
}

fn segments_match(prefix: &str, handler_parts: &[&str], request_parts: &[&str]) -> bool {
    let offset = if !prefix.is_empty() {
        if handler_parts.len() as i32 != request_parts.len() as i32 - 1
            || prefix != request_parts[0]
        {
            return false;
        }
        1
    } else {
        if handler_parts.len() != request_parts.len() {
            return false;
        }
        0
    };

    for (i, p) in handler_parts.iter().enumerate() {
        if p == &"*" {
            continue;
        }

        if p != &request_parts[i + offset] {
            return false;
        }
    }
    true
}

fn is_health_probe_route(prefix: &str, handler_parts: &[&str], method: &Method) -> bool {
    (*method == Method::GET || *method == Method::HEAD)
        && prefix.is_empty()
        && handler_parts.len() == 2
        && handler_parts[0] == "health"
        && matches!(handler_parts[1], "alive" | "ready" | "started")
}

type BodyKindFuture = Pin<Box<dyn futures_util::Future<Output = BodyKind> + Send>>;

impl RequestHandlers {
    pub fn push<T>(&mut self, request_handler: T)
    where
        T: RequestHandler + Send + Sync + 'static,
    {
        self.handlers.push(Arc::new(
            Box::new(request_handler) as Box<dyn RequestHandler + Send + Sync + 'static>
        ));
    }

    fn call<R>(
        &self,
        client_identifier: Arc<ClientIdentifier>,
        endpoint_policy: Arc<EndpointPolicy>,
        peer_addr: Option<SocketAddr>,
        req: hyper::Request<R>,
    ) -> BodyKindFuture
    where
        R: hyper::body::Body + Send + 'static,
        <R as hyper::body::Body>::Error: std::error::Error,
        <R as hyper::body::Body>::Data: Send,
    {
        let callbacks = self.handlers.clone();

        Box::pin(async move {
            let segments = req
                .uri()
                .path()
                .split('/')
                // handles double slashes e.g. /scans/ or /scans//id////results
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>();

            for rh in callbacks {
                if segments_match(rh.prefix(), rh.path_segments(), &segments) {
                    if is_health_probe_route(rh.prefix(), rh.path_segments(), req.method())
                        && !endpoint_policy.allows_health_peer(peer_addr)
                    {
                        return BodyKind::no_content(StatusCode::FORBIDDEN);
                    }

                    let needs_authentication = rh.needs_authentication();
                    let is_authenticated =
                        matches!(&*client_identifier, &ClientIdentifier::Known(_));
                    if !needs_authentication || is_authenticated {
                        tracing::debug!(
                            "Handling request: {}/{}",
                            rh.prefix(),
                            rh.path_segments().join("/")
                        );

                        if (req.method() == Method::HEAD
                            && rh.path_segments()[0] == "scans"
                            && is_authenticated)
                            || (req.method() == Method::HEAD && rh.path_segments()[0] != "scans")
                        {
                            return BodyKind::no_content(StatusCode::OK);
                        };

                        if req.method() == rh.http_method() {
                            let uri = req.uri().clone();
                            let body = req.into_body();
                            let bytes = match body.collect().await {
                                Ok(x) => x.to_bytes(),
                                Err(e) => {
                                    return internal_server_error!(e);
                                }
                            };

                            return rh.call(client_identifier, &uri, bytes).await;
                        }
                    } else {
                        return BodyKind::no_content(StatusCode::UNAUTHORIZED);
                    }
                }
            }

            BodyKind::no_content(StatusCode::NOT_FOUND)
        })
    }
}

pub struct EntryPoint {
    scanner: Arc<super::Scanner>,
    handlers: Arc<RequestHandlers>,
    client_identifier: Arc<ClientIdentifier>,
    endpoint_policy: Arc<EndpointPolicy>,
    peer_addr: Option<SocketAddr>,
    max_connections: usize,
    counter: Arc<AtomicUsize>,
}

impl EntryPoint {
    pub fn new(
        scanner: Arc<super::Scanner>,
        client_identifier: Arc<ClientIdentifier>,
        handlers: Arc<RequestHandlers>,
        endpoint_policy: Arc<EndpointPolicy>,
        peer_addr: Option<SocketAddr>,
        max_connections: usize,
        counter: Arc<AtomicUsize>,
    ) -> EntryPoint {
        EntryPoint {
            max_connections,
            scanner,
            client_identifier,
            handlers,
            endpoint_policy,
            peer_addr,
            counter,
        }
    }
}

use http_body_util::BodyExt;

fn api_key_to_client_identifier(
    api_keys: &[String],
    header: Option<&HeaderValue>,
) -> ClientIdentifier {
    let used_key = match header {
        Some(x) => match x.to_str() {
            Ok(y) => y.to_owned(),
            Err(e) => {
                tracing::debug!(error=%e, "header contains invalid ascii symbol");
                "".to_owned()
            }
        },
        None => "".to_owned(),
    };
    // we iterate through each time so that the time on success and failure is relatively equal
    let mut result = ClientIdentifier::Unknown;
    for x in api_keys {
        if x == &used_key {
            result = ClientIdentifier::Known(x.into());
        }
    }
    tracing::debug!(
        known_api_key = matches!(result, ClientIdentifier::Known(_)),
        "has used known api key"
    );
    result
}

fn should_hide_metadata_headers(
    hide_declined_response_headers: bool,
    status_code: StatusCode,
) -> bool {
    hide_declined_response_headers
        && matches!(
            status_code,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        )
}

fn feed_version_header(feed_version: &Arc<std::sync::RwLock<crate::models::FeedState>>) -> String {
    match &*feed_version.read().unwrap() {
        crate::models::FeedState::Unknown => "unavailable".to_string(),
        crate::models::FeedState::Syncing => "unavailable".to_string(),
        crate::models::FeedState::Synced(vt, adv) => format!("{vt}{adv}"),
    }
}

use crate::{Authentication, MapScanID, internal_server_error};

impl<R> hyper::service::Service<hyper::Request<R>> for EntryPoint
where
    R: hyper::body::Body + Send + 'static,
    <R as hyper::body::Body>::Error: std::error::Error,
    <R as hyper::body::Body>::Data: Send,
{
    type Response = hyper::Response<BodyKindContent>;

    type Error = Infallible;

    type Future =
        Pin<Box<dyn futures_util::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: hyper::Request<R>) -> Self::Future {
        let cbs = self.scanner.clone();
        let cid = match &self.scanner.authentication {
            Authentication::Disabled => Arc::new(ClientIdentifier::Known(Default::default())),
            Authentication::MTLS => self.client_identifier.clone(),
            Authentication::ApiKey(keys) => Arc::new(api_key_to_client_identifier(
                keys,
                req.headers().get("x-api-key"),
            )),
        };
        let incoming = self.handlers.clone();
        let endpoint_policy = self.endpoint_policy.clone();
        let peer_addr = self.peer_addr;
        let hide_declined_response_headers = endpoint_policy.hide_declined_response_headers;
        let authentication = cbs.authentication.static_str();
        let api_version = cbs.api_version.clone();
        let feed_version = cbs.feed_version.clone();

        let acc = self.counter.clone();
        let max_connections = self.max_connections;
        Box::pin(async move {
            if acc.load(Ordering::Relaxed) > max_connections {
                tracing::trace!("Too many open connections, returning 503");
                return Ok(hyper::Response::builder()
                    .header("authentication", authentication)
                    .header("api-version", &api_version)
                    .header("feed-version", feed_version_header(&feed_version))
                    .header("Retry-After", 10)
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(BodyKindContent::Empty)
                    .unwrap());
            }

            let current = acc.fetch_add(1, Ordering::Relaxed);
            tracing::trace!(current, max_connections, "handling request");
            let resp = incoming.call(cid, endpoint_policy, peer_addr, req).await;
            let rb = hyper::Response::builder();
            let rb =
                if should_hide_metadata_headers(hide_declined_response_headers, resp.status_code) {
                    rb
                } else {
                    rb.header("authentication", authentication)
                        .header("api-version", &api_version)
                        .header("feed-version", feed_version_header(&feed_version))
                };
            let rb = match &resp.content {
                BodyKindContent::Empty => rb,
                BodyKindContent::Binary(x) => rb
                    .header("Content-Type", "application/json")
                    .header("Content-Length", x.len()),
                BodyKindContent::BinaryStream(_) => rb.header("Content-Type", "application/json"),
            };
            let current = acc.fetch_sub(1, Ordering::Relaxed);
            tracing::trace!(current, max_connections, "releasing request");

            Ok(rb.status(resp.status_code).body(resp.content).unwrap())
        })
    }
}

pub(crate) fn enforce_client_hash(client_id: &Arc<ClientIdentifier>) -> &ClientHash {
    match client_id.as_ref() {
        crate::ClientIdentifier::Unknown => {
            unreachable!("get_scans is marked as authenticated, no unknown clients should pass")
        }
        crate::ClientIdentifier::Known(client_hash) => client_hash,
    }
}

pub async fn enforce_client_id_and_scan_id<T, F, Fut>(
    client_id: &Arc<ClientIdentifier>,
    scan_id: String,
    verifier: &T,
    f: F,
) -> BodyKind
where
    T: MapScanID,
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = BodyKind>,
{
    let client = enforce_client_hash(client_id).to_string();
    if let Some(id) = verifier.contains_scan_id(&client, &scan_id).await {
        f(id).await
    } else {
        BodyKind::no_content(StatusCode::NOT_FOUND)
    }
}

pub mod test_utilities {
    use std::{
        net::SocketAddr,
        pin::Pin,
        sync::{Arc, RwLock},
    };

    use http_body_util::{Empty, Full};
    use hyper::{Request, body::Bytes};

    use super::{
        ClientHash, ClientIdentifier, EndpointPolicy, EntryPoint, Method, RequestHandlers,
    };
    use crate::{Authentication, Scanner, models::FeedState};

    pub fn entry_point(
        authentication: Authentication,
        handlers: RequestHandlers,
        client_hash: Option<ClientHash>,
    ) -> EntryPoint {
        entry_point_with_policy(
            authentication,
            handlers,
            client_hash,
            Default::default(),
            None,
        )
    }

    pub fn entry_point_with_policy(
        authentication: Authentication,
        handlers: RequestHandlers,
        client_hash: Option<ClientHash>,
        endpoint_policy: EndpointPolicy,
        peer_addr: Option<SocketAddr>,
    ) -> EntryPoint {
        let configuration = Arc::new(Scanner {
            api_version: "test".to_owned(),
            authentication,
            feed_version: Arc::new(RwLock::new(FeedState::Synced(
                "vt".to_string(),
                "advisories".to_string(),
            ))),
        });

        let client_identifier = Arc::new(match client_hash {
            Some(x) => ClientIdentifier::Known(x),
            None => ClientIdentifier::Unknown,
        });
        let ir = Arc::new(handlers);
        EntryPoint::new(
            configuration,
            client_identifier,
            ir,
            Arc::new(endpoint_policy),
            peer_addr,
            10,
            Default::default(),
        )
    }

    pub fn empty_request(method: Method, uri: &str) -> Request<Empty<Bytes>> {
        Request::builder()
            .uri(uri)
            .method(method)
            .body(Empty::<Bytes>::new())
            .unwrap()
    }

    pub fn json_request<T>(method: Method, uri: &str, value: &T) -> Request<Full<Bytes>>
    where
        T: serde::Serialize,
    {
        Request::builder()
            .uri(uri)
            .method(method)
            .body(json_bytes(value))
            .unwrap()
    }

    pub fn json_bytes<T>(value: &T) -> Full<Bytes>
    where
        T: serde::Serialize,
    {
        let json = serde_json::to_vec(value).expect("value should be serializable");
        Full::from(json)
    }

    pub fn on_client_id_return<A, B>(
        client_id: String,
        f: A,
        e: B,
    ) -> Pin<Box<dyn Future<Output = Result<A, B>> + Send>>
    where
        A: Sync + Send + 'static,
        B: From<std::io::Error> + Sync + Send + 'static,
    {
        let client_id = client_id.clone();
        let ok = ClientHash::from("ok").to_string();
        let not_found = ClientHash::from("not_found").to_string();
        Box::pin(async move {
            if client_id == ok {
                return Ok(f);
            }
            if client_id == not_found {
                return Err(e);
            }

            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "").into())
        })
    }
}
#[cfg(test)]
mod tests {
    use http_body_util::Empty;
    use hyper::{Request, header::HeaderValue, service::Service};

    use super::*;
    use crate::Authentication;

    fn assert_no_metadata_headers<T>(resp: &hyper::Response<T>) {
        let headers = resp.headers();
        assert!(headers.get("authentication").is_none());
        assert!(headers.get("api-version").is_none());
        assert!(headers.get("feed-version").is_none());
    }

    fn assert_metadata_headers<T>(resp: &hyper::Response<T>, authentication: HeaderValue) {
        let headers = resp.headers();
        assert_eq!(headers.get("authentication").unwrap(), authentication);
        assert_eq!(
            headers.get("api-version").unwrap(),
            HeaderValue::from_static("test")
        );
        assert_eq!(
            headers.get("feed-version").unwrap(),
            HeaderValue::from_static("vtadvisories")
        );
    }

    struct IdPart {}

    impl Prefixed for IdPart {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl RequestHandler for IdPart {
        auth_method_segments!(authenticated: true, Method::GET, "test", "id", "*");
        fn call<'a, 'b>(
            &'b self,
            _: Arc<ClientIdentifier>,
            uri: &'a Uri,
            _: Bytes,
        ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
        where
            'b: 'a,
        {
            let ids = self.ids(uri);
            Box::pin(async move {
                BodyKind::json_content(StatusCode::OK, &ids.first().unwrap().to_owned())
            })
        }
    }
    struct Authenticated {}
    impl Prefixed for Authenticated {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl RequestHandler for Authenticated {
        auth_method_segments!(authenticated: true, Method::GET, "test", "authn");
        fn call<'a, 'b>(
            &'b self,
            _: Arc<ClientIdentifier>,
            _: &'a Uri,
            _: Bytes,
        ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
        where
            'b: 'a,
        {
            Box::pin(
                async move { BodyKind::json_content(StatusCode::OK, &"test_response".to_owned()) },
            )
        }
    }

    struct NotAuthenticated {}

    impl Prefixed for NotAuthenticated {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl RequestHandler for NotAuthenticated {
        auth_method_segments!(authenticated: false, Method::GET, "test", "not_authn");
        fn call<'a, 'b>(
            &'b self,
            _: Arc<ClientIdentifier>,
            _: &'a Uri,
            _: Bytes,
        ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
        where
            'b: 'a,
        {
            Box::pin(async move { BodyKind::no_content(StatusCode::OK) })
        }
    }

    struct HealthReady {}

    impl Prefixed for HealthReady {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl RequestHandler for HealthReady {
        auth_method_segments!(authenticated: false, Method::GET, "health", "ready");

        fn call<'a, 'b>(
            &'b self,
            _: Arc<ClientIdentifier>,
            _: &'a Uri,
            _: Bytes,
        ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
        where
            'b: 'a,
        {
            Box::pin(async move { BodyKind::no_content(StatusCode::OK) })
        }
    }

    #[tokio::test]
    async fn contains_header_information_on_head() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(Authenticated {}),
            Some(ClientHash::default()),
        );
        let req = test_utilities::empty_request(Method::HEAD, "/test////authn//////");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();
        assert_eq!(
            headers.get("authentication").unwrap(),
            HeaderValue::from_static("mTLS")
        );
        assert_eq!(
            headers.get("api-version").unwrap(),
            HeaderValue::from_static("test")
        );

        assert_eq!(
            headers.get("feed-version").unwrap(),
            HeaderValue::from_static("vtadvisories")
        );

        let resp = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(resp.is_empty());
    }

    #[tokio::test]
    async fn contains_content_type_and_len() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(IdPart {}),
            Some(ClientHash::default()),
        );
        let req = test_utilities::empty_request(Method::GET, "/test/id/itsame");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            HeaderValue::from_static("application/json")
        );

        assert_eq!(
            resp.headers().get("Content-Length").unwrap(),
            HeaderValue::from_static("8")
        );
    }

    #[tokio::test]
    async fn id_path() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(IdPart {}),
            Some(ClientHash::default()),
        );
        let req = test_utilities::empty_request(Method::GET, "/test/id/itsame");
        let resp = entry_point.call(req).await.unwrap();
        let resp = resp.into_body().collect().await.unwrap().to_bytes();

        let returned = String::from_utf8_lossy(resp.as_ref());
        assert_eq!(returned, "\"itsame\"");
    }
    #[tokio::test]
    async fn id_path_missing_id() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(IdPart {}),
            Some(ClientHash::default()),
        );
        let req = test_utilities::empty_request(Method::GET, "/test/id///");
        let resp = entry_point.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn not_found() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(Authenticated {}, NotAuthenticated {}),
            Some(ClientHash::default()),
        );
        let req = test_utilities::empty_request(Method::POST, "/test/authn");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_client_id_on_mtls() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(Authenticated {}),
            None,
        );

        let req = test_utilities::empty_request(Method::HEAD, "/test/authn");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_metadata_headers(&resp, HeaderValue::from_static("mTLS"));
    }

    #[tokio::test]
    async fn missing_api_key() {
        let entry_point = test_utilities::entry_point(
            Authentication::ApiKey(vec!["test".to_owned()]),
            create_single_handler!(Authenticated {}),
            Some(Default::default()),
        );

        let req = test_utilities::empty_request(Method::HEAD, "/test/authn");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_metadata_headers(&resp, HeaderValue::from_static("api-key"));
    }

    #[tokio::test]
    async fn declined_auth_hides_metadata_headers_when_configured() {
        let entry_point = test_utilities::entry_point_with_policy(
            Authentication::MTLS,
            create_single_handler!(Authenticated {}),
            None,
            EndpointPolicy::new(vec![]).hide_declined_response_headers(true),
            None,
        );

        let req = test_utilities::empty_request(Method::HEAD, "/test/authn");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_no_metadata_headers(&resp);
    }

    #[tokio::test]
    async fn api_key() {
        let entry_point = test_utilities::entry_point(
            Authentication::ApiKey(vec!["test".to_owned()]),
            create_single_handler!(Authenticated {}),
            Some(Default::default()),
        );

        let req = Request::builder()
            .uri("/test/authn")
            .header("x-api-key", "test")
            .method(Method::HEAD)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_allowlist_allows_matching_peer() {
        let entry_point = test_utilities::entry_point_with_policy(
            Authentication::MTLS,
            create_single_handler!(HealthReady {}),
            None,
            EndpointPolicy::new(vec!["127.0.0.0/8".parse().unwrap()]),
            Some(([127, 0, 0, 1], 1234).into()),
        );

        let req = test_utilities::empty_request(Method::GET, "/health/ready");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let req = test_utilities::empty_request(Method::HEAD, "/health/ready");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_allowlist_denies_non_matching_peer() {
        let entry_point = test_utilities::entry_point_with_policy(
            Authentication::MTLS,
            create_single_handler!(HealthReady {}),
            None,
            EndpointPolicy::new(vec!["127.0.0.1".parse().unwrap()]),
            Some(([192, 0, 2, 1], 1234).into()),
        );

        let req = test_utilities::empty_request(Method::GET, "/health/ready");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_metadata_headers(&resp, HeaderValue::from_static("mTLS"));

        let req = test_utilities::empty_request(Method::HEAD, "/health/ready");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_metadata_headers(&resp, HeaderValue::from_static("mTLS"));
    }

    #[tokio::test]
    async fn health_allowlist_hides_declined_metadata_headers_when_configured() {
        let entry_point = test_utilities::entry_point_with_policy(
            Authentication::MTLS,
            create_single_handler!(HealthReady {}),
            None,
            EndpointPolicy::new(vec!["127.0.0.1".parse().unwrap()])
                .hide_declined_response_headers(true),
            Some(([192, 0, 2, 1], 1234).into()),
        );

        let req = test_utilities::empty_request(Method::GET, "/health/ready");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_no_metadata_headers(&resp);

        let req = test_utilities::empty_request(Method::HEAD, "/health/ready");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_no_metadata_headers(&resp);
    }

    #[tokio::test]
    async fn health_allowlist_keeps_unimplemented_health_routes_not_found() {
        let entry_point = test_utilities::entry_point_with_policy(
            Authentication::MTLS,
            create_single_handler!(HealthReady {}),
            None,
            EndpointPolicy::new(vec!["127.0.0.1".parse().unwrap()]),
            Some(([192, 0, 2, 1], 1234).into()),
        );

        let req = test_utilities::empty_request(Method::GET, "/health");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = test_utilities::empty_request(Method::POST, "/health/ready");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = test_utilities::empty_request(Method::GET, "/health/unknown");
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    struct PrefixedAuth {}
    impl Prefixed for PrefixedAuth {
        fn prefix(&self) -> &'static str {
            "achso"
        }
    }

    impl RequestHandler for PrefixedAuth {
        auth_method_segments!(authenticated: true, Method::GET, "test", "wtf");
        fn call<'a, 'b>(
            &'b self,
            _: Arc<ClientIdentifier>,
            _: &'a Uri,
            _: Bytes,
        ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
        where
            'b: 'a,
        {
            Box::pin(
                async move { BodyKind::json_content(StatusCode::OK, &"test_response".to_owned()) },
            )
        }
    }

    #[tokio::test]
    async fn prefixed() {
        let entry_point = test_utilities::entry_point(
            Authentication::ApiKey(vec!["test".to_owned()]),
            create_single_handler!(PrefixedAuth {}),
            Some(Default::default()),
        );

        let req = Request::builder()
            .uri("/achso/test/wtf")
            .header("x-api-key", "test")
            .method(Method::HEAD)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn prefixed_no_path() {
        let entry_point = test_utilities::entry_point(
            Authentication::ApiKey(vec!["test".to_owned()]),
            create_single_handler!(PrefixedAuth {}),
            Some(Default::default()),
        );

        let req = Request::builder()
            .uri("/achso")
            .header("x-api-key", "test")
            .method(Method::HEAD)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
