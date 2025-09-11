use std::pin::Pin;

use hyper::StatusCode;

use crate::{
    Endpoint, Handler, auth_method_segments_new,
    endpoint::InputData,
    entry::{Method, response::BodyKind},
};

pub enum Started {
    Started,
    NotStarted,
}

impl From<Started> for StatusCode {
    fn from(val: Started) -> Self {
        match val {
            Started::Started => StatusCode::NO_CONTENT,
            Started::NotStarted => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub struct GetHealthStarted;

impl Endpoint for GetHealthStarted {
    type In = ();
    type Out = Started;

    auth_method_segments_new!(
        authenticated: false,
        Method::GET,
        "health", "started"
    );

    fn data_to_input(_: InputData) -> Self::In {
        ()
    }

    fn output_to_data(started: Started) -> BodyKind {
        BodyKind::no_content(started.into())
    }
}

#[derive(Default)]
pub struct AlwaysStarted;

impl Handler<GetHealthStarted> for AlwaysStarted {
    fn call(&self, _: ()) -> Pin<Box<dyn Future<Output = Started> + Send>> {
        Box::pin(async move { Started::Started })
    }
}

#[cfg(test)]
mod tests {
    use super::{AlwaysStarted, GetHealthStarted, Started, *};
    use crate::{Handler, entry::test_utilities};

    struct NeverStarted;

    impl Handler<GetHealthStarted> for NeverStarted {
        fn call(&self, _: ()) -> Pin<Box<dyn Future<Output = Started> + Send>> {
            Box::pin(async move { Started::NotStarted })
        }
    }

    #[tokio::test]
    async fn get_health_started() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthStarted,
            AlwaysStarted,
            "/health/started",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_started() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthStarted,
            NeverStarted,
            "/health/started",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
