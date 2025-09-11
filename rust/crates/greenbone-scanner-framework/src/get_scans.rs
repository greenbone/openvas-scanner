use std::{fmt::Debug, pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    Endpoint, ExternalError, auth_method_segments, auth_method_segments_new,
    endpoint::InputData,
    entry::{
        self, Bytes, Method, Prefixed, RequestHandler,
        response::{BodyKind, StreamResult},
    },
    internal_server_error,
};

pub struct GetScansE;

impl Endpoint for GetScansE {
    type In = String;

    type Out = Result<Vec<String>, GetScansError>;

    auth_method_segments_new!(
        authenticated: true,
        Method::GET,
        "scans"
    );

    fn data_to_input(data: InputData) -> Self::In {
        entry::enforce_client_hash(&data.client_id).to_string()
    }

    fn output_to_data(_: Self::Out) -> BodyKind {
        todo!()
    }
}

pub trait GetScans: Send + Sync {
    fn get_scans(&self, client_id: String) -> StreamResult<'static, String, GetScansError>;
}

pub struct GetScansHandler<T> {
    get_scans: Arc<T>,
}

impl<T> Prefixed for GetScansHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans.prefix()
    }
}

impl<S> RequestHandler for GetScansHandler<S>
where
    S: GetScans + Prefixed + 'static,
{
    auth_method_segments!(
        authenticated: true,
        Method::GET,
        "scans"
    );

    fn call<'a, 'b>(
        &'b self,
        client_id: Arc<entry::ClientIdentifier>,
        _: &'a entry::Uri,
        _: Bytes,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_scans.clone();
        Box::pin(async move {
            let input = gsp.get_scans(entry::enforce_client_hash(&client_id).to_string());
            BodyKind::from_result_stream(StatusCode::OK, input).await
        })
    }
}

impl<T> From<T> for GetScansHandler<T>
where
    T: GetScans + 'static,
{
    fn from(value: T) -> Self {
        GetScansHandler {
            get_scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetScansHandler<T>
where
    T: GetScans + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetScansHandler { get_scans: value }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetScansError {
    // TODO: GetScansID uses this, should be moved to there
    #[error("Not found.")]
    NotFound,
    #[error("Unexpected error occurred: {0}.")]
    External(Box<dyn ExternalError>),
}

impl From<std::io::Error> for GetScansError {
    fn from(value: std::io::Error) -> Self {
        Self::External(Box::new(value))
    }
}

impl GetScansError {
    pub fn from_external<E>(err: E) -> Self
    where
        E: ExternalError + Send + Sync + 'static,
    {
        Self::External(Box::new(err))
    }
}

impl From<GetScansError> for BodyKind {
    fn from(e: GetScansError) -> Self {
        match e {
            GetScansError::NotFound => BodyKind::no_content(StatusCode::NOT_FOUND),
            GetScansError::External(external_error) => internal_server_error!(external_error),
        }
    }
}

#[cfg(test)]
mod tests {
    use entry::test_utilities;
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};
    use tokio::io;

    use super::*;
    use crate::{Authentication, ClientHash, Handler, Handlers};

    struct Test;

    impl Handler<GetScansE> for Test {
        fn call(
            &self,
            client_id: String,
        ) -> Pin<Box<dyn std::future::Future<Output = <GetScansE as Endpoint>::Out> + Send>>
        {
            let ise = ClientHash::from("internal_server_error").to_string();
            if ise == client_id {
                Box::pin(async move {
                    Err(GetScansError::External(Box::new(io::Error::other("oh no"))))
                })
            } else {
                Box::pin(async move { Ok(vec![String::default()]) })
            }
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point_new(
            Authentication::MTLS,
            Handlers::single(GetScansE, Test),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_scans() {
        let entry_point = test_utilities::entry_point_new(
            Authentication::MTLS,
            Handlers::single(GetScansE, Test),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans")
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
