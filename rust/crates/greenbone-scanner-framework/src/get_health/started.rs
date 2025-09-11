use std::convert::Infallible;

use hyper::StatusCode;

use crate::{
    Endpoint, auth_method_segments_new,
    endpoint::InputData,
    entry::{Method, response::BodyKind},
};

#[derive(Clone)]
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
    type InErr = Infallible;

    auth_method_segments_new!(
        authenticated: false,
        Method::GET,
        "health", "started"
    );

    fn data_to_input(_: InputData) -> Result<Self::In, Self::InErr> {
        Ok(())
    }

    fn output_to_data(started: Started) -> BodyKind {
        BodyKind::no_content(started.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{GetHealthStarted, Started, *};
    use crate::{entry::test_utilities, get_health::Always};

    #[tokio::test]
    async fn get_health_started() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthStarted,
            Always(Started::Started),
            "/health/started",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_health_not_started() {
        let response = test_utilities::test_endpoint_handler(
            GetHealthStarted,
            Always(Started::NotStarted),
            "/health/started",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
