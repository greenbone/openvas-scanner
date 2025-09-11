use std::pin::Pin;

use hyper::StatusCode;

use crate::{
    Endpoint, Handler, auth_method_segments_new,
    endpoint::InputData,
    entry::{Method, response::BodyKind},
};

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

pub struct GetHealthAlive;

impl Endpoint for GetHealthAlive {
    type In = ();
    type Out = Alive;

    auth_method_segments_new!(
        authenticated: false,
        Method::GET,
        "health", "alive"
    );

    fn data_to_input(_: InputData) -> Self::In {
        ()
    }

    fn output_to_data(alive: Alive) -> BodyKind {
        BodyKind::no_content(alive.into())
    }
}

#[derive(Default)]
pub struct AlwaysAlive;

impl Handler<GetHealthAlive> for AlwaysAlive {
    fn call(&self, _: ()) -> Pin<Box<dyn Future<Output = Alive> + Send>> {
        Box::pin(async move { Alive::Alive })
    }
}

#[cfg(test)]
mod tests {
    use super::{Alive, AlwaysAlive, GetHealthAlive, *};
    use crate::{Handler, entry::test_utilities};

    struct NeverAlive;

    impl Handler<GetHealthAlive> for NeverAlive {
        fn call(&self, _: ()) -> Pin<Box<dyn Future<Output = Alive> + Send>> {
            Box::pin(async move { Alive::NotAlive })
        }
    }

    #[tokio::test]
    async fn get_health_alive() {
        let response =
            test_utilities::test_endpoint_handler(GetHealthAlive, AlwaysAlive, "/health/alive")
                .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_alive() {
        let response =
            test_utilities::test_endpoint_handler(GetHealthAlive, NeverAlive, "/health/alive")
                .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
