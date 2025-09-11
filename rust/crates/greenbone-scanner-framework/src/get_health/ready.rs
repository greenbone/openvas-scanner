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
    use http_body_util::Empty;
    use hyper::{Request, Response, service::Service};

    use super::{AlwaysReady, GetHealthReady, Ready, *};
    use crate::{
        Authentication, ClientHash, Handler, Handlers,
        entry::{Bytes, response::BodyKindContent, test_utilities},
    };

    struct NeverReady;

    impl Handler<GetHealthReady> for NeverReady {
        fn call(&self, _: ()) -> Pin<Box<dyn Future<Output = Ready> + Send>> {
            Box::pin(async move { Ready::NotReady })
        }
    }

    async fn test_health_ready_handler<H: Handler<GetHealthReady> + Send + Sync + 'static>(
        handler: H,
    ) -> Response<BodyKindContent> {
        let entry_point = test_utilities::entry_point_new(
            Authentication::MTLS,
            Handlers::single(GetHealthReady, handler),
            Some(ClientHash::from("ok")),
        );
        let req = Request::builder()
            .uri("/health/ready")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();

        entry_point.call(req).await.unwrap()
    }

    #[tokio::test]
    async fn get_health_ready() {
        let response = test_health_ready_handler(AlwaysReady).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_ready() {
        let response = test_health_ready_handler(NeverReady).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
