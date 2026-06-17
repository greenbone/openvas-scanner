use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    ExternalError, StreamResult,
    entry::{self, Bytes, Method, Prefixed, RequestHandler, response::BodyKind},
    internal_server_error,
    models::VTData,
};

pub trait GetVts: Send + Sync {
    fn get_oids(&self, client_id: String) -> StreamResult<String, GetVTsError>;

    fn get_vts(&self, client_id: String) -> StreamResult<VTData, GetVTsError>;
}

pub struct GetVTsHandler<T> {
    get_scans: Arc<T>,
    require_authentication: bool,
}

impl<T> GetVTsHandler<T> {
    pub fn require_authentication(mut self, require_authentication: bool) -> Self {
        self.require_authentication = require_authentication;
        self
    }
}

impl<T> Prefixed for GetVTsHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans.prefix()
    }
}

impl<S> RequestHandler for GetVTsHandler<S>
where
    S: GetVts + Prefixed + 'static,
{
    fn needs_authentication(&self) -> bool {
        self.require_authentication
    }

    fn path_segments(&self) -> &'static [&'static str] {
        &["vts"]
    }

    fn http_method(&self) -> Method {
        Method::GET
    }

    fn call<'a, 'b>(
        &'b self,
        client_id: Arc<entry::ClientIdentifier>,
        uri: &'a entry::Uri,
        _: Bytes,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_scans.clone();
        let details = match uri.query() {
            Some("information=true") => true,
            Some("information=1") => true,
            Some(_) | None => false,
        };

        let client_id = match client_id.as_ref() {
            crate::ClientIdentifier::Unknown => "unknown".to_string(),
            crate::ClientIdentifier::Known(client_hash) => client_hash.to_string(),
        };

        Box::pin(async move {
            if details {
                BodyKind::from_result_stream(StatusCode::OK, gsp.get_vts(client_id)).await
            } else {
                BodyKind::from_result_stream(StatusCode::OK, gsp.get_oids(client_id)).await
            }
        })
    }
}

impl<T> From<T> for GetVTsHandler<T>
where
    T: GetVts + 'static,
{
    fn from(value: T) -> Self {
        GetVTsHandler {
            get_scans: Arc::new(value),
            require_authentication: false,
        }
    }
}

impl<T> From<Arc<T>> for GetVTsHandler<T>
where
    T: GetVts + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetVTsHandler {
            get_scans: value,
            require_authentication: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetVTsError {
    #[error("Not yet available.")]
    NotYetAvailable,

    #[error("{0}")]
    External(Box<dyn ExternalError + Send + Sync + 'static>),
}

impl From<GetVTsError> for BodyKind {
    fn from(e: GetVTsError) -> Self {
        match e {
            GetVTsError::External(external_error) => internal_server_error!(external_error),
            GetVTsError::NotYetAvailable => BodyKind::no_content(StatusCode::SERVICE_UNAVAILABLE),
        }
    }
}

#[cfg(test)]
mod tests {

    use entry::test_utilities;
    use futures::stream;
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};

    use super::*;
    use crate::{Authentication, ClientHash, create_single_handler};

    struct Test {}

    impl Prefixed for Test {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl GetVts for Test {
        fn get_oids(&self, client_id: String) -> StreamResult<String, GetVTsError> {
            let ok = ClientHash::from("ok").to_string();
            let not_found = ClientHash::from("not_found").to_string();
            let unknown = "unknown".to_string();
            let result = if client_id == unknown || client_id == ok {
                vec![Ok(client_id)]
            } else if client_id == not_found {
                vec![Err(GetVTsError::NotYetAvailable)]
            } else {
                vec![Err(GetVTsError::External(Box::new(std::io::Error::other(
                    "moep",
                ))))]
            };
            //stream::iter(result)
            Box::pin(stream::iter(result))
        }

        fn get_vts(&self, _: String) -> StreamResult<VTData, GetVTsError> {
            Box::pin(stream::iter(vec![Ok(VTData::default())]))
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetVTsHandler::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/vts")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn not_yet_available() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetVTsHandler::from(Test {})),
            Some(ClientHash::from("not_found")),
        );

        let req = Request::builder()
            .uri("/vts")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn get_vts_authenticated() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetVTsHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/vts")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp = String::from_utf8_lossy(bytes.as_ref());
        insta::assert_snapshot!(resp);
    }

    #[tokio::test]
    async fn get_vts_detailed() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetVTsHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/vts?information=true")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let first: Vec<VTData> = serde_json::from_slice(&bytes).unwrap();
        let req = Request::builder()
            .uri("/vts?information=1")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let second: Vec<VTData> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(first, second)
    }

    #[tokio::test]
    async fn get_vts_unauthenticated() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetVTsHandler::from(Test {})),
            None,
        );

        let req = Request::builder()
            .uri("/vts")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp = String::from_utf8_lossy(bytes.as_ref());
        insta::assert_snapshot!(resp);
    }

    #[tokio::test]
    async fn get_vts_requires_authentication_when_enabled() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetVTsHandler::from(Test {}).require_authentication(true)),
            None,
        );

        let req = Request::builder()
            .uri("/vts")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::builder()
            .uri("/vts")
            .method(Method::HEAD)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_vts_with_required_authentication_allows_known_client() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetVTsHandler::from(Test {}).require_authentication(true)),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/vts")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let req = Request::builder()
            .uri("/vts")
            .method(Method::HEAD)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
