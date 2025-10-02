//! Entry contains every module struct which is considered and entry point
//!
//! An entry point handles each incoming request, it checks if an endpoint
//! requires client-id/api-key and adds all required header information for each
//! response.

use std::{convert::Infallible, fmt::Display, pin::Pin, sync::Arc};
pub mod response;

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
        if handler_parts.len() != request_parts.len() - 1 || prefix != request_parts[0] {
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
                    let needs_authentication = rh.needs_authentication();
                    let is_authenticated =
                        matches!(&*client_identifier, &ClientIdentifier::Known(_));
                    if !needs_authentication || is_authenticated {
                        info!(
                            "Handling request: {}/{}",
                            rh.prefix(),
                            rh.path_segments().join("/")
                        );
                        if req.method() == Method::HEAD {
                            return BodyKind::no_content(StatusCode::OK);
                        }
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
}

impl EntryPoint {
    pub fn new(
        scanner: Arc<super::Scanner>,
        client_identifier: Arc<ClientIdentifier>,
        handlers: Arc<RequestHandlers>,
    ) -> EntryPoint {
        EntryPoint {
            scanner,
            client_identifier,
            handlers,
        }
    }
}

use http_body_util::BodyExt;
use tracing::info;

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
        let feed_version = match &*cbs.feed_version.read().unwrap() {
            crate::models::FeedState::Unknown => "unavailable".to_string(),
            crate::models::FeedState::Syncing => "unavailable".to_string(),
            crate::models::FeedState::Synced(vt, adv) => format!("{vt}{adv}"),
        };
        let rb = hyper::Response::builder()
            .header("authentication", cbs.authentication.static_str())
            .header("api-version", &cbs.api_version)
            .header("feed-version", &feed_version);
        let incoming = self.handlers.clone();

        Box::pin(async move {
            let resp = incoming.call(cid, req).await;
            let rb = match &resp.content {
                BodyKindContent::Empty => rb,
                BodyKindContent::Binary(x) => rb
                    .header("Content-Type", "application/json")
                    .header("Content-Length", x.len()),
                BodyKindContent::BinaryStream(_) => rb.header("Content-Type", "application/json"),
            };

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
        pin::Pin,
        sync::{Arc, RwLock},
    };

    use http_body_util::{Empty, Full};
    use hyper::{Request, body::Bytes};

    use super::{ClientHash, ClientIdentifier, EntryPoint, Method, RequestHandlers};
    use crate::{Authentication, Scanner, models::FeedState};

    pub fn entry_point(
        authentication: Authentication,
        handlers: RequestHandlers,
        client_hash: Option<ClientHash>,
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
        EntryPoint::new(configuration, client_identifier, ir)
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
        for (method, url) in [
            (Method::HEAD, "/test/authn/not"),
            (Method::POST, "/test/authn"),
        ] {
            let req = test_utilities::empty_request(method, url);
            let resp = entry_point.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
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
}
