use std::sync::Arc;

use hyper::StatusCode;

use crate::{
    ContainsScanID, ExternalError, define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, enforce_client_id_and_scan_id, response::BodyKind},
    internal_server_error,
    models::Action,
};

pub trait PostScansID: ContainsScanID {
    fn post_scans_id(
        &self,
        client_id: String,
        scan_id: String,
        action: Action,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), PostScansIDError>> + Send + '_>>;
}

pub struct PostScansIDIncomingRequest<T> {
    scans: Arc<T>,
}

impl<S> OnRequest for PostScansIDIncomingRequest<S>
where
    S: PostScansID + 'static,
{
    define_authentication_paths!(
        authenticated: true,
        Method::POST,
        "scans", "*"
    );

    fn call<'a, 'b>(
        &'b self,
        client_id: Arc<entry::ClientIdentifier>,
        uri: &'a entry::Uri,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.scans.clone();
        let id = self
            .ids(uri)
            .into_iter()
            .next()
            .expect("expect ID, this is a toolkit error");
        Box::pin(async move {
            match serde_json::from_slice::<crate::models::ScanAction>(&body) {
                Ok(scan) => {
                    enforce_client_id_and_scan_id(
                        &client_id,
                        id,
                        gsp.as_ref(),
                        async |client_id, id| match gsp
                            .post_scans_id(client_id, id, scan.action)
                            .await
                        {
                            Ok(()) => BodyKind::no_content(StatusCode::NO_CONTENT),
                            Err(e) => e.into(),
                        },
                    )
                    .await
                }

                Err(e) => e.into(),
            }
        })
    }
}

impl<T> From<T> for PostScansIDIncomingRequest<T>
where
    T: PostScansID + 'static,
{
    fn from(value: T) -> Self {
        PostScansIDIncomingRequest {
            scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for PostScansIDIncomingRequest<T>
where
    T: PostScansID + 'static,
{
    fn from(value: Arc<T>) -> Self {
        PostScansIDIncomingRequest { scans: value }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PostScansIDError {
    #[error("ALready running.")]
    Running,
    #[error("Unexpected error occoured: {0}.")]
    External(Box<dyn ExternalError>),
}

impl From<std::io::Error> for PostScansIDError {
    fn from(value: std::io::Error) -> Self {
        Self::External(Box::new(value))
    }
}

impl PostScansIDError {
    pub fn from_external<E>(err: E) -> Self
    where
        E: ExternalError + Send + Sync + 'static,
    {
        Self::External(Box::new(err))
    }
}

impl From<PostScansIDError> for BodyKind {
    fn from(e: PostScansIDError) -> Self {
        match e {
            PostScansIDError::External(e) => internal_server_error!(e),
            PostScansIDError::Running => BodyKind::no_content(StatusCode::NOT_ACCEPTABLE),
        }
    }
}

#[cfg(test)]
mod tests {
    use entry::test_utilities::{self, json_bytes};
    use http_body_util::Empty;
    use hyper::{Method, Request, service::Service};

    use crate::{Authentication, ClientHash, incoming_request, models::ScanAction};

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

    impl PostScansID for Test {
        fn post_scans_id(
            &self,
            client_id: String,
            _: String,
            action: Action,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), PostScansIDError>> + Send>> {
            let client_id = client_id.clone();
            let ok = ClientHash::from("ok").to_string();
            let already_running = ClientHash::from("already_running").to_string();
            Box::pin(async move {
                if client_id == ok {
                    return Ok(());
                }
                if client_id == already_running && action == Action::Start {
                    return Err(PostScansIDError::Running);
                }

                Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "").into())
            })
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(PostScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );
        let scans = ScanAction {
            action: Action::Start,
        };

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::POST)
            .body(json_bytes(&scans))
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn missing_scan() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(PostScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/not_found")
            .method(Method::POST)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn already_running() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(PostScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("already_running")),
        );
        let scans = ScanAction {
            action: Action::Start,
        };

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::POST)
            .body(json_bytes(&scans))
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn ok() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(PostScansIDIncomingRequest::from(Test {})),
            Some(ClientHash::from("ok")),
        );
        let scans = ScanAction {
            action: Action::Start,
        };

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::POST)
            .body(json_bytes(&scans))
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
