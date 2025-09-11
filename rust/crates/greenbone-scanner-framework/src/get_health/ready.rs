use hyper::StatusCode;

use crate::{
    Endpoint, auth_method_segments_new,
    endpoint::InputData,
    entry::{Method, response::BodyKind},
};

#[derive(Clone)]
pub enum Ready {
    Ready,
    NotReady,
}

impl From<Ready> for StatusCode {
    fn from(val: Ready) -> Self {
        match val {
            Ready::Ready => StatusCode::NO_CONTENT,
            Ready::NotReady => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub struct GetHealthReady;

impl Endpoint for GetHealthReady {
    type In = ();
    type Out = Ready;

    auth_method_segments_new!(
        authenticated: false,
        Method::GET,
        "health", "ready"
    );

    fn data_to_input(_: InputData) -> Self::In {
        ()
    }

    fn output_to_data(ready: Ready) -> BodyKind {
        BodyKind::no_content(ready.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{GetHealthReady, Ready, *};
    use crate::{entry::test_utilities, get_health::Always};

    #[tokio::test]
    async fn get_health_ready() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthReady,
            Always(Ready::Ready),
            "/health/ready",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_ready() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthReady,
            Always(Ready::NotReady),
            "/health/ready",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
