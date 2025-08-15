use std::sync::Arc;

use hyper::StatusCode;

use crate::{
    define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, Prefixed, response::BodyKind},
};

pub trait GetHealthAlive: Prefixed + Send + Sync {
    fn get_health_alive(&self) -> std::pin::Pin<Box<dyn Future<Output = Alive> + Send>>;
}

pub enum Alive {
    Alive,
    NotAlive,
}

impl From<Alive> for StatusCode {
    fn from(val: Alive) -> Self {
        match val {
            Alive::Alive => StatusCode::NO_CONTENT,
            Alive::NotAlive => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub struct GetHealthAliveIncomingRequest<T> {
    get_health_alive: Arc<T>,
}

#[derive(Default)]
pub struct JustAlive;

impl Prefixed for JustAlive {
    fn prefix(&self) -> &'static str {
        ""
    }
}

impl GetHealthAlive for JustAlive {
    fn get_health_alive(&self) -> std::pin::Pin<Box<dyn Future<Output = Alive> + Send>> {
        Box::pin(async move { Alive::Alive })
    }
}
impl Default for GetHealthAliveIncomingRequest<JustAlive> {
    fn default() -> Self {
        Self {
            get_health_alive: Arc::new(JustAlive {}),
        }
    }
}

impl<S> Prefixed for GetHealthAliveIncomingRequest<S>
where
    S: Prefixed + 'static,
{
    fn prefix(&self) -> &'static str {
        self.get_health_alive.prefix()
    }
}

impl<S> OnRequest for GetHealthAliveIncomingRequest<S>
where
    S: GetHealthAlive + 'static,
{
    define_authentication_paths!(
        authenticated: false,
        Method::GET,
        "health", "alive"
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
        let gsp = self.get_health_alive.clone();
        Box::pin(async move { BodyKind::no_content(gsp.get_health_alive().await.into()) })
    }
}

impl<T> From<T> for GetHealthAliveIncomingRequest<T>
where
    T: GetHealthAlive + 'static,
{
    fn from(value: T) -> Self {
        GetHealthAliveIncomingRequest {
            get_health_alive: Arc::new(value),
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

    struct NotAlive {}

    impl Prefixed for NotAlive {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl GetHealthAlive for NotAlive {
        fn get_health_alive(&self) -> std::pin::Pin<Box<dyn Future<Output = Alive> + Send>> {
            Box::pin(async move { super::Alive::NotAlive })
        }
    }

    #[tokio::test]
    async fn get_health_alive() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetHealthAliveIncomingRequest::from(super::JustAlive {})),
            None,
        );

        let req = Request::builder()
            .uri("/health/alive")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_alive() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetHealthAliveIncomingRequest::from(NotAlive {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/health/alive")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
