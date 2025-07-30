use std::sync::Arc;

use hyper::StatusCode;

use crate::{
    define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, response::BodyKind},
};

pub trait GetHealthStarted: Send + Sync {
    fn get_health_started(&self) -> std::pin::Pin<Box<dyn Future<Output = Started> + Send>>;
}

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

pub struct GetHealthStartedIncomingRequest<T> {
    get_health_started: Arc<T>,
}

#[derive(Default)]
pub struct JustStarted;

impl GetHealthStarted for JustStarted {
    fn get_health_started(&self) -> std::pin::Pin<Box<dyn Future<Output = Started> + Send>> {
        Box::pin(async move { Started::Started })
    }
}
impl Default for GetHealthStartedIncomingRequest<JustStarted> {
    fn default() -> Self {
        Self {
            get_health_started: Arc::new(JustStarted {}),
        }
    }
}

impl<S> OnRequest for GetHealthStartedIncomingRequest<S>
where
    S: GetHealthStarted + 'static,
{
    define_authentication_paths!(
        authenticated: false,
        Method::GET,
        "health", "started"
    );

    fn call<'a, 'b>(
        &'b self,
        _: Arc<entry::ClientIdentifier>,
        _: &'a entry::Uri,
        _: Bytes,
    ) -> std::pin::Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_health_started.clone();
        Box::pin(async move { BodyKind::no_content(gsp.get_health_started().await.into()) })
    }
}

impl<T> From<T> for GetHealthStartedIncomingRequest<T>
where
    T: GetHealthStarted + 'static,
{
    fn from(value: T) -> Self {
        GetHealthStartedIncomingRequest {
            get_health_started: Arc::new(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use entry::test_utilities;
    use http_body_util::Empty;
    use hyper::{Request, service::Service};

    use crate::{Authentication, ClientHash, incoming_request};

    use super::*;

    struct NotStarted {}

    impl GetHealthStarted for NotStarted {
        fn get_health_started(&self) -> std::pin::Pin<Box<dyn Future<Output = Started> + Send>> {
            Box::pin(async move { super::Started::NotStarted })
        }
    }

    #[tokio::test]
    async fn get_health_started() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetHealthStartedIncomingRequest::from(super::JustStarted {})),
            None,
        );

        let req = Request::builder()
            .uri("/health/started")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_started() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetHealthStartedIncomingRequest::from(NotStarted {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/health/started")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
