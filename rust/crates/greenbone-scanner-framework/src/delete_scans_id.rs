use std::sync::Arc;

use hyper::StatusCode;

use crate::{
    MapScanID, define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, enforce_client_id_and_scan_id, response::BodyKind},
    post_scans_id::PostScansIDError,
};

pub trait DeleteScansID: MapScanID {
    fn delete_scans_id(
        &self,
        id: String,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send + '_>>;
}

pub struct DeleteScansIDIncomingRequest<T> {
    handler: Arc<T>,
}

impl<S> OnRequest for DeleteScansIDIncomingRequest<S>
where
    S: DeleteScansID + 'static,
{
    define_authentication_paths!(
        authenticated: true,
        Method::DELETE,
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
        let gsp = self.handler.clone();
        let id = self
            .ids(uri)
            .into_iter()
            .next()
            .expect("expect ID, this is a toolkit error");
        Box::pin(async move {
            enforce_client_id_and_scan_id(&client_id, id, gsp.as_ref(), async |id| {
                match gsp.delete_scans_id(id).await {
                    Ok(()) => BodyKind::no_content(StatusCode::NO_CONTENT),
                    Err(e) => e.into(),
                }
            })
            .await
        })
    }
}

impl<T> From<T> for DeleteScansIDIncomingRequest<T>
where
    T: DeleteScansID + 'static,
{
    fn from(value: T) -> Self {
        DeleteScansIDIncomingRequest {
            handler: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for DeleteScansIDIncomingRequest<T>
where
    T: DeleteScansID + 'static,
{
    fn from(value: Arc<T>) -> Self {
        DeleteScansIDIncomingRequest { handler: value }
    }
}

pub type DeleteScansIDError = PostScansIDError;

#[cfg(test)]
mod tests {
    use entry::test_utilities::{self};
    use http_body_util::Empty;
    use hyper::{Method, Request, service::Service};

    use crate::{Authentication, ClientHash, incoming_request};

    use super::*;

    struct Test {}

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

    impl DeleteScansID for Test {
        fn delete_scans_id(
            &self,
            id: String,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send>>
        {
            let client_id = id.clone();
            let ok = ClientHash::from("ok").to_string();
            let already_running = ClientHash::from("already_running").to_string();
            Box::pin(async move {
                if client_id == ok {
                    return Ok(());
                }
                if client_id == already_running {
                    return Err(DeleteScansIDError::Running);
                }

                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "").into())
            })
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(DeleteScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn missing_scan() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(DeleteScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/not_found")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn already_running() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(DeleteScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("already_running")),
        );

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn ok() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(DeleteScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
