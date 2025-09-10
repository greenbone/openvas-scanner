use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    auth_method_segments,
    entry::{self, Bytes, Method, Prefixed, RequestHandler, response::BodyKind},
};

pub trait GetHealthStarted: Send + Sync {
    fn get_health_started(&self) -> Pin<Box<dyn Future<Output = Started> + Send>>;
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

pub struct GetHealthStartedHandler<T> {
    get_health_started: Arc<T>,
}

impl<T> Prefixed for GetHealthStartedHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_health_started.prefix()
    }
}

#[derive(Default)]
pub struct JustStarted;

impl Prefixed for JustStarted {
    fn prefix(&self) -> &'static str {
        ""
    }
}

impl GetHealthStarted for JustStarted {
    fn get_health_started(&self) -> Pin<Box<dyn Future<Output = Started> + Send>> {
        Box::pin(async move { Started::Started })
    }
}
impl Default for GetHealthStartedHandler<JustStarted> {
    fn default() -> Self {
        Self {
            get_health_started: Arc::new(JustStarted {}),
        }
    }
}

impl<S> RequestHandler for GetHealthStartedHandler<S>
where
    S: GetHealthStarted + Prefixed + 'static,
{
    auth_method_segments!(
        authenticated: false,
        Method::GET,
        "health", "started"
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
        let gsp = self.get_health_started.clone();
        Box::pin(async move { BodyKind::no_content(gsp.get_health_started().await.into()) })
    }
}

impl<T> From<T> for GetHealthStartedHandler<T>
where
    T: GetHealthStarted + 'static,
{
    fn from(value: T) -> Self {
        GetHealthStartedHandler {
            get_health_started: Arc::new(value),
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

    struct NotStarted {}

    impl Prefixed for NotStarted {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl GetHealthStarted for NotStarted {
        fn get_health_started(&self) -> Pin<Box<dyn Future<Output = Started> + Send>> {
            Box::pin(async move { super::Started::NotStarted })
        }
    }

    #[tokio::test]
    async fn get_health_started() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetHealthStartedHandler::from(super::JustStarted {})),
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
            create_single_handler!(GetHealthStartedHandler::from(NotStarted {})),
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
