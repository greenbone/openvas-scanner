use rocket::{
    async_trait,
    http::Status,
    log::private::debug,
    mtls::{self, Certificate},
    request::{FromRequest, Outcome},
    Request,
};

use crate::{config::Auth, error::ApiError};

pub struct Authorizer;

#[derive(Debug)]
pub enum AuthorizationError<'a> {
    KeyInvalid,
    KeyMissing,
    CertificateInvalid,
    CertificateMissing,
    ParseError(mtls::Error),
    InvalidAuthMethod(&'a str),
    InternalSerialError(&'a str),
}

#[async_trait]
impl<'r> FromRequest<'r> for Authorizer {
    type Error = AuthorizationError<'r>;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Retrieve the config state like this
        let config = req.rocket().state::<Auth>().unwrap();

        let method = &config.auth_method;

        debug!("Auth method: {method}");

        match method.as_str() {
            "api_key" => match req.headers().get_one("api-key") {
                None => {
                    req.local_cache(|| {
                        Some(<AuthorizationError as Into<ApiError>>::into(
                            AuthorizationError::KeyMissing,
                        ))
                    });
                    return Outcome::Failure((
                        Status::Unauthorized,
                        AuthorizationError::KeyMissing,
                    ));
                }
                Some(key) if key == config.api_key => return Outcome::Success(Authorizer),
                Some(_) => {
                    req.local_cache(|| {
                        Some(<AuthorizationError as Into<ApiError>>::into(
                            AuthorizationError::KeyInvalid,
                        ))
                    });
                    return Outcome::Failure((
                        Status::Unauthorized,
                        AuthorizationError::KeyInvalid,
                    ));
                }
            },
            "certificate" => {
                let cert = match req.guard::<Certificate<'r>>().await {
                    Outcome::Success(c) => c,
                    Outcome::Failure((_, e)) => {
                        req.local_cache(|| {
                            Some(<AuthorizationError as Into<ApiError>>::into(
                                AuthorizationError::ParseError(e.clone()),
                            ))
                        });
                        return Outcome::Failure((
                            Status::Unauthorized,
                            AuthorizationError::ParseError(e),
                        ));
                    }
                    Outcome::Forward(()) => {
                        req.local_cache(|| {
                            Some(<AuthorizationError as Into<ApiError>>::into(
                                AuthorizationError::CertificateMissing,
                            ))
                        });
                        return Outcome::Failure((
                            Status::Unauthorized,
                            AuthorizationError::CertificateMissing,
                        ));
                    }
                };

                match cert.has_serial("01") {
                    Some(true) => {
                        return Outcome::Success(Authorizer);
                    }
                    Some(_) => {
                        req.local_cache(|| {
                            Some(<AuthorizationError as Into<ApiError>>::into(
                                AuthorizationError::CertificateInvalid,
                            ))
                        });
                        return Outcome::Failure((
                            Status::Unauthorized,
                            AuthorizationError::CertificateInvalid,
                        ));
                    }
                    None => {
                        req.local_cache(|| {
                            Some(<AuthorizationError as Into<ApiError>>::into(
                                AuthorizationError::InternalSerialError("01"),
                            ))
                        });
                        return Outcome::Failure((
                            Status::InternalServerError,
                            AuthorizationError::InternalSerialError("01"),
                        ));
                    }
                }
            }
            inv => {
                req.local_cache(|| {
                    Some(<AuthorizationError as Into<ApiError>>::into(
                        AuthorizationError::InvalidAuthMethod(inv),
                    ))
                });
                return Outcome::Failure((
                    Status::Unauthorized,
                    AuthorizationError::InvalidAuthMethod(inv),
                ));
            }
        }
    }
}
