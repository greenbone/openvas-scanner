use std::sync::Arc;

use crate::{ExternalError, StreamResult, models::VTData};
use hyper::StatusCode;

use crate::{
    define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, response::BodyKind},
    internal_server_error,
};

pub trait GetVts: Send + Sync {
    fn get_oids(
        &self,
        client_id: Arc<entry::ClientIdentifier>,
    ) -> StreamResult<'static, String, GetVTsError>;

    fn get_vts(
        &self,
        client_id: Arc<entry::ClientIdentifier>,
    ) -> StreamResult<'static, VTData, GetVTsError>;
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
        _: &'a entry::Uri,
        _: Bytes,
    ) -> std::pin::Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_scans.clone();
        Box::pin(async move {
            match gsp.get_oids(client_id).await {
                Ok(x) => BodyKind::json_content(StatusCode::OK, &x),
                Err(e) => e.into(),
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

pub enum GetVTsError {
    NotYetAvailable,
    External(Box<dyn ExternalError + Send + Sync + 'static>),
}

impl<T> From<T> for GetVTsError
where
    T: std::error::Error + Send + Sync + 'static,
{
    fn from(value: T) -> Self {
        Self::External(Box::new(value))
    }
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
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};

    use crate::{Authentication, ClientHash, ClientIdentifier, incoming_request};

    use super::*;

    struct Test {}

    impl GetVts for Test {
        fn get_oids(
            &self,
            client_id: Arc<ClientIdentifier>,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<String>, GetVTsError>> + Send>>
        {
            let client_id = client_id.clone();
            let ok = ClientHash::from("ok");
            let not_found = ClientHash::from("not_found");
            Box::pin(async move {
                match client_id.as_ref() {
                    ClientIdentifier::Unknown => Ok(vec![]),
                    ClientIdentifier::Known(client_id) => {
                        if client_id == &ok {
                            return Ok(vec![]);
                        }
                        if client_id == &not_found {
                            return Err(GetVTsError::NotYetAvailable);
                        }

                        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "").into())
                    }
                }
            })
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
