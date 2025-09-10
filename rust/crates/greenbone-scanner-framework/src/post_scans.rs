use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    ExternalError, auth_method_segments,
    entry::{self, Bytes, Prefixed, RequestHandler, enforce_client_hash, response::BodyKind},
    internal_server_error, models,
};

pub trait PostScans: Send + Sync {
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send + '_>>;
}

pub struct PostScansHandler<T> {
    store_scan: Arc<T>,
}

impl<T> Prefixed for PostScansHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.store_scan.prefix()
    }
}

impl<S> RequestHandler for PostScansHandler<S>
where
    S: PostScans + Prefixed + 'static,
{
    auth_method_segments!(authenticated: true, crate::entry::Method::POST, "scans");

    fn call<'a, 'b>(
        &'b self,
        client_id: Arc<entry::ClientIdentifier>,
        _: &'a entry::Uri,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let store_scan = self.store_scan.clone();
        Box::pin(async move {
            match serde_json::from_slice::<models::Scan>(&body) {
                Ok(mut scan) => {
                    if scan.scan_id.is_empty() {
                        scan.scan_id = uuid::Uuid::new_v4().into();
                    }
                    match store_scan
                        .post_scans(enforce_client_hash(&client_id).to_string(), scan)
                        .await
                    {
                        Ok(id) => BodyKind::json_content(hyper::StatusCode::CREATED, &id),
                        Err(e) => e.into(),
                    }
                }
                Err(e) => e.into(),
            }
        })
    }
}

impl<T> From<T> for PostScansHandler<T>
where
    T: PostScans + 'static,
{
    fn from(value: T) -> Self {
        PostScansHandler {
            store_scan: Arc::new(value),
        }
    }
}
impl<T> From<Arc<T>> for PostScansHandler<T>
where
    T: PostScans + 'static,
{
    fn from(value: Arc<T>) -> Self {
        PostScansHandler { store_scan: value }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PostScansError {
    #[error("ID ({0}) is already in use.")]
    DuplicateId(String),
    #[error("Unexpected error occurred: {0}.")]
    External(Box<dyn ExternalError>),
}

impl From<std::io::Error> for PostScansError {
    fn from(value: std::io::Error) -> Self {
        Self::External(Box::new(value))
    }
}

impl PostScansError {
    pub fn from_external<E>(err: E) -> Self
    where
        E: ExternalError + Send + Sync + 'static,
    {
        Self::External(Box::new(err))
    }
}

impl From<PostScansError> for BodyKind {
    fn from(val: PostScansError) -> Self {
        match val {
            PostScansError::DuplicateId(id) => {
                let br = format!("ID ({id}) is already in use.");
                BodyKind::json_content(StatusCode::NOT_ACCEPTABLE, &br)
            }
            PostScansError::External(e) => internal_server_error!(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use entry::test_utilities::{self, json_bytes};
    use http_body_util::{BodyExt, Empty};
    use hyper::{Method, Request, service::Service};

    use super::*;
    use crate::{Authentication, ClientHash, create_single_handler};

    struct Test {}
    impl Prefixed for Test {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl PostScans for Test {
        fn post_scans(
            &self,
            client_id: String,
            _: models::Scan,
        ) -> Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send>> {
            let result = "response_id".to_owned();

            test_utilities::on_client_id_return(
                client_id,
                result,
                PostScansError::DuplicateId("duplicate".to_owned()),
            )
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(PostScansHandler::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );
        let scans = models::Scan::default();

        let req = Request::builder()
            .uri("/scans")
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
            create_single_handler!(PostScansHandler::from(Test {})),
            Some(ClientHash::from("not_found")),
        );

        let req = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn duplicate_id() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(PostScansHandler::from(Test {})),
            Some(ClientHash::from("not_found")),
        );
        let scans = models::Scan::default();

        let req = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(json_bytes(&scans))
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn post_scans() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(PostScansHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );
        let scans = models::Scan::default();

        let req = Request::builder()
            .uri("/scans")
            .method(Method::POST)
            .body(json_bytes(&scans))
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp = String::from_utf8_lossy(bytes.as_ref());
        insta::assert_snapshot!(resp);
    }
}
