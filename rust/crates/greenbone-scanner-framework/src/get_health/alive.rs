use std::convert::Infallible;

use hyper::StatusCode;

use crate::{
    Endpoint, auth_method_segments_new,
    endpoint::InputData,
    entry::{Method, response::BodyKind},
};

#[derive(Clone)]
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
    type InErr = Infallible;

    auth_method_segments_new!(
        authenticated: false,
        Method::GET,
        "health", "alive"
    );

    fn data_to_input(_: InputData) -> Result<Self::In, Self::InErr> {
        Ok(())
    }

    fn output_to_data(alive: Alive) -> BodyKind {
        BodyKind::no_content(alive.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Alive, GetHealthAlive, *};
    use crate::{entry::test_utilities, get_health::Always};

    #[tokio::test]
    async fn get_health_alive() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthAlive,
            Always(Alive::Alive),
            "/health/alive",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_alive() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthAlive,
            Always(Alive::NotAlive),
            "/health/alive",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
