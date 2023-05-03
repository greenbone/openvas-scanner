use rocket::{
    async_trait,
    http::Status,
    request::{FromRequest, Outcome},
    Request,
};

use crate::{config::Config, error::APIError};

/// API Key validator
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiKey<'r>(&'r str);

#[derive(Debug)]
pub enum ApiKeyError {
    Invalid,
    Missing,
}

#[async_trait]
impl<'r> FromRequest<'r> for ApiKey<'r> {
    type Error = ApiKeyError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Retrieve the config state like this
        let config = req.rocket().state::<Config>().unwrap();

        match req.headers().get_one("api-key") {
            None => {
                req.local_cache(|| {
                    Some(<ApiKeyError as Into<APIError>>::into(ApiKeyError::Missing))
                });
                Outcome::Failure((Status::Unauthorized, ApiKeyError::Missing))
            }
            Some(key) if key == config.api_key => Outcome::Success(ApiKey(key)),
            Some(_) => {
                req.local_cache(|| {
                    Some(<ApiKeyError as Into<APIError>>::into(ApiKeyError::Invalid))
                });
                Outcome::Failure((Status::Unauthorized, ApiKeyError::Invalid))
            }
        }
    }
}
