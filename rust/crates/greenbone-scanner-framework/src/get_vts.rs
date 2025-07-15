use std::sync::Arc;

use crate::{ExternalError, StreamResult, models::VTData};
use hyper::StatusCode;

use crate::{
    define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, response::BodyKind},
    internal_server_error,
};

pub trait GetVts: Send + Sync {
    fn get_oids(&self, client_id: String) -> StreamResult<'static, String, GetVTsError>;

    fn get_vts(&self, client_id: String) -> StreamResult<'static, VTData, GetVTsError>;
}

pub struct GetVTsIncomingRequest<T> {
    get_scans: Arc<T>,
}

impl<S> OnRequest for GetVTsIncomingRequest<S>
where
    S: GetVts + 'static,
{
    define_authentication_paths!(
        authenticated: false,
        Method::GET,
        "vts"
    );

    fn call<'a, 'b>(
        &'b self,
        client_id: Arc<entry::ClientIdentifier>,
        uri: &'a entry::Uri,
        _: Bytes,
    ) -> std::pin::Pin<Box<dyn Future<Output = BodyKind> + Send>>
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

impl<T> From<T> for GetVTsIncomingRequest<T>
where
    T: GetVts + 'static,
{
    fn from(value: T) -> Self {
        GetVTsIncomingRequest {
            get_scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetVTsIncomingRequest<T>
where
    T: GetVts + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetVTsIncomingRequest { get_scans: value }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetVTsError {
    #[error("Not yet available.")]
    NotYetAvailable,

    #[error("Unexpected error occoured: {0}.")]
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

    use crate::{Authentication, ClientHash, ClientIdentifier, incoming_request};

    use super::*;

    struct Test {}

    impl GetVts for Test {
        fn get_oids(&self, client_id: String) -> StreamResult<'static, String, GetVTsError> {
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
            Box::new(stream::iter(result))
        }

        fn get_vts(&self, _: String) -> StreamResult<'static, VTData, GetVTsError> {
            Box::new(stream::iter(vec![Ok(VTData::default())]))
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetVTsIncomingRequest::from(Test {})),
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
            incoming_request!(GetVTsIncomingRequest::from(Test {})),
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
            incoming_request!(GetVTsIncomingRequest::from(Test {})),
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
            incoming_request!(GetVTsIncomingRequest::from(Test {})),
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
            incoming_request!(GetVTsIncomingRequest::from(Test {})),
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
}
