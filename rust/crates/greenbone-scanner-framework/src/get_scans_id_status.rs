use std::sync::Arc;

use hyper::StatusCode;

use crate::{
    GetScansError, MapScanID, define_authentication_paths,
    entry::{
        self, Bytes, Method, OnRequest, Prefixed, enforce_client_id_and_scan_id, response::BodyKind,
    },
    models,
};

pub trait GetScansIDStatus: MapScanID {
    fn get_scans_id_status(
        &self,
        id: String,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>,
    >;
}

pub struct GetScansIDStatusIncomingRequest<T> {
    get_scans: Arc<T>,
}

impl<T> Prefixed for GetScansIDStatusIncomingRequest<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans.prefix()
    }
}

impl<S> OnRequest for GetScansIDStatusIncomingRequest<S>
where
    S: GetScansIDStatus + Prefixed + 'static,
{
    define_authentication_paths!(
        authenticated: true,
        Method::GET,
        "scans", "*", "status"
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
            enforce_client_id_and_scan_id(&client_id, id, gsp.as_ref(), async |id| {
                match gsp.get_scans_id_status(id).await {
                    Ok(x) => BodyKind::json_content(StatusCode::OK, &x),
                    Err(e) => e.into(),
                }
            })
            .await
        })
    }
}

impl<T> From<T> for GetScansIDStatusIncomingRequest<T>
where
    T: GetScansIDStatus + 'static,
{
    fn from(value: T) -> Self {
        GetScansIDStatusIncomingRequest {
            get_scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetScansIDStatusIncomingRequest<T>
where
    T: GetScansIDStatus + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetScansIDStatusIncomingRequest { get_scans: value }
    }
}

pub type GetScansIDStatusError = GetScansError;

#[cfg(test)]
mod tests {
    use entry::test_utilities;
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};

    use crate::{Authentication, ClientHash, incoming_request};

    use super::*;

    struct Test {}

    impl Prefixed for Test {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl MapScanID for Test {
        fn contains_scan_id<'a>(
            &'a self,
            client_id: &'a str,
            scan_id: &'a str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
            Box::pin(async move {
                if scan_id == "id" {
                    Some(client_id.to_string())
                } else {
                    None
                }
            })
        }
    }

    impl GetScansIDStatus for Test {
        fn get_scans_id_status(
            &self,
            client_id: String,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send>,
        > {
            let result = models::Status {
                ..Default::default()
            };
            test_utilities::on_client_id_return(client_id, result, GetScansError::NotFound)
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetScansIDStatusIncomingRequest::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans/id/status")
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
            incoming_request!(GetScansIDStatusIncomingRequest::from(Test {})),
            Some(ClientHash::from("not_found")),
        );

        let req = Request::builder()
            .uri("/scans/not_found/status")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_status() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetScansIDStatusIncomingRequest::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id/status")
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
