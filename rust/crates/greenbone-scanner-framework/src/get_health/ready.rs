use std::pin::Pin;

use hyper::StatusCode;

use crate::{
    Endpoint, Handler, auth_method_segments_new,
    endpoint::InputData,
    entry::{Method, response::BodyKind},
};

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

#[derive(Default)]
pub struct AlwaysReady;

impl Handler<GetHealthReady> for AlwaysReady {
    fn call(&self, _: ()) -> Pin<Box<dyn Future<Output = Ready> + Send>> {
        Box::pin(async move { Ready::Ready })
    }
}

#[cfg(test)]
mod tests {
    use super::{AlwaysReady, GetHealthReady, Ready, *};
    use crate::{Handler, entry::test_utilities};

    struct NeverReady;

    impl Handler<GetHealthReady> for NeverReady {
        fn call(&self, _: ()) -> Pin<Box<dyn Future<Output = Ready> + Send>> {
            Box::pin(async move { Ready::NotReady })
        }
    }

    #[tokio::test]
    async fn get_health_ready() {
        let response =
            test_utilities::test_endpoint_handler(GetHealthReady, AlwaysReady, "/health/ready")
                .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_ready() {
        let response =
            test_utilities::test_endpoint_handler(GetHealthReady, NeverReady, "/health/ready")
                .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
