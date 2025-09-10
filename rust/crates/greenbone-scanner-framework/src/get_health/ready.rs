use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    auth_method_segments,
    entry::{self, Bytes, Method, Prefixed, RequestHandler, response::BodyKind},
};

pub trait GetHealthReady: Prefixed + Send + Sync {
    fn get_health_ready(&self) -> Pin<Box<dyn Future<Output = Ready> + Send>>;
}

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

pub struct GetHealthReadyHandler<T> {
    get_health_ready: Arc<T>,
}

impl<T> Prefixed for GetHealthReadyHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_health_ready.prefix()
    }
}

#[derive(Default)]
pub struct JustReady;

impl Prefixed for JustReady {
    fn prefix(&self) -> &'static str {
        ""
    }
}

impl GetHealthReady for JustReady {
    fn get_health_ready(&self) -> Pin<Box<dyn Future<Output = Ready> + Send>> {
        Box::pin(async move { Ready::Ready })
    }
}
impl Default for GetHealthReadyHandler<JustReady> {
    fn default() -> Self {
        Self {
            get_health_ready: Arc::new(JustReady {}),
        }
    }
}

impl<S> RequestHandler for GetHealthReadyHandler<S>
where
    S: GetHealthReady + Prefixed + 'static,
{
    auth_method_segments!(
        authenticated: false,
        Method::GET,
        "health", "ready"
    );

    fn call<'a, 'b>(
        &'b self,
        _: Arc<entry::ClientIdentifier>,
        _: &'a entry::Uri,
        _: Bytes,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_health_ready.clone();
        Box::pin(async move { BodyKind::no_content(gsp.get_health_ready().await.into()) })
    }
}

impl<T> From<T> for GetHealthReadyHandler<T>
where
    T: GetHealthReady + 'static,
{
    fn from(value: T) -> Self {
        GetHealthReadyHandler {
            get_health_ready: Arc::new(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use entry::test_utilities;
    use http_body_util::Empty;
    use hyper::{Request, service::Service};

    use super::*;
    use crate::{Authentication, ClientHash, create_single_handler};

    struct NotReady {}

    impl GetHealthReady for NotReady {
        fn get_health_ready(&self) -> Pin<Box<dyn Future<Output = Ready> + Send>> {
            Box::pin(async move { super::Ready::NotReady })
        }
    }

    impl Prefixed for NotReady {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    #[tokio::test]
    async fn get_health_ready() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetHealthReadyHandler::from(super::JustReady {})),
            None,
        );

        let req = Request::builder()
            .uri("/health/ready")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_ready() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetHealthReadyHandler::from(NotReady {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/health/ready")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
