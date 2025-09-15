use std::{fmt::Debug, pin::Pin};

use futures::Stream;
use hyper::StatusCode;

use crate::{
    ExternalError, auth_method_segments_new,
    endpoint::{InputData, StreamEndpoint},
    entry::{self, Method, response::BodyKind},
    internal_server_error,
};

pub struct GetScans;

impl StreamEndpoint for GetScans {
    type In = String;
    type Item = Result<String, GetScansError>;

    auth_method_segments_new!(
        authenticated: true,
        Method::GET,
        "scans"
    );

    fn data_to_input(data: InputData) -> Self::In {
        entry::enforce_client_hash(&data.client_id).to_string()
    }

    fn output_to_data(
        stream: impl Stream<Item = Self::Item> + Send + Unpin + 'static,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send + 'static>> {
        Box::pin(
            async move { BodyKind::from_result_stream(StatusCode::OK, Box::new(stream)).await },
        )
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
    use futures::stream;
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};
    use tokio::io;

    use super::*;
    use crate::{
        Authentication, ClientHash, Handlers, StreamHandler, StreamHandlerOutput, entry::Bytes,
    };

    struct Test;

    impl StreamHandler<GetScans> for Test {
        fn call(&self, client_id: String) -> StreamHandlerOutput<GetScans> {
            let ise = ClientHash::from("internal_server_error").to_string();
            if ise == client_id {
                Box::pin(stream::iter(vec![Err(GetScansError::External(Box::new(
                    io::Error::other("oh no"),
                )))]))
            } else {
                Box::pin(stream::iter(vec![Ok(String::default())]))
            }
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point_new(
            Authentication::MTLS,
            Handlers::single_stream(GetScans, Test),
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
            Handlers::single_stream(GetScans, Test),
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
