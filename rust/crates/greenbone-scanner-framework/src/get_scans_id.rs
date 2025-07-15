use std::sync::Arc;

use hyper::StatusCode;

use crate::{
    ContainsScanID, GetScansError, define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, enforce_client_id_and_scan_id, response::BodyKind},
    models,
};

pub trait GetScansID: ContainsScanID {
    fn get_scans_id(
        &self,
        client_id: String,
        scan_id: String,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send>>;
}

pub struct GetScansIDIncomingRequest<T> {
    get_scans: Arc<T>,
}

impl<S> OnRequest for GetScansIDIncomingRequest<S>
where
    S: GetScansID + 'static,
{
    define_authentication_paths!(
        authenticated: true,
        Method::GET,
        "scans", "*"
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
        let id = self
            .ids(uri)
            .into_iter()
            .next()
            .expect("expect ID, this is a toolkit error");
        Box::pin(async move {
            enforce_client_id_and_scan_id(&client_id, id, gsp.as_ref(), async |client_id, id| {
                match gsp.get_scans_id(client_id, id).await {
                    Ok(x) => BodyKind::json_content(StatusCode::OK, &x),
                    Err(e) => e.into(),
                }
            })
            .await
        })
    }
}

impl<T> From<T> for GetScansIDIncomingRequest<T>
where
    T: GetScansID + 'static,
{
    fn from(value: T) -> Self {
        GetScansIDIncomingRequest {
            get_scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetScansIDIncomingRequest<T>
where
    T: GetScansID + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetScansIDIncomingRequest { get_scans: value }
    }
}

pub type GetScansIDError = GetScansError;

#[cfg(test)]
mod tests {
    use entry::test_utilities;
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};

    use crate::{Authentication, ClientHash, incoming_request};

    use super::*;

    struct Test {}

    impl ContainsScanID for Test {
        fn contains_scan_id<'a>(
            &'a self,
            _: &'a str,
            scan_id: &'a str,
        ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async move { scan_id == "id" })
        }
    }

    impl GetScansID for Test {
        fn get_scans_id(
            &self,
            client_id: String,
            scan_id: String,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send>>
        {
            let result = models::Scan {
                scan_id,
                ..Default::default()
            };
            test_utilities::on_client_id_return(client_id, result, GetScansError::NotFound)
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn not_found() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("not_found")),
        );

        let req = Request::builder()
            .uri("/scans/not_found")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_scans() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id")
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
