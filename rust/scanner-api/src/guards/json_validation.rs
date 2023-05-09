use std::{io, ops::Deref};

use rocket::{
    async_trait,
    data::{ByteUnit, FromData, Outcome},
    http::Status,
    request::local_cache,
    Data, Request,
};
use serde::Deserialize;

use crate::error::ApiError;

/// Custom JSON validator request guard to translate its errors into a respond
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonValidation<T>(pub T);

/// Error returned by the [`Json`] guard when JSON deserialization fails.
#[derive(Debug)]
pub enum JsonValidationError<'a> {
    /// An I/O error occurred while reading the incoming request data.
    Io(io::Error),

    /// The client's data was received successfully but failed to parse as valid
    /// JSON or as the requested type. The `&str` value in `.0` is the raw data
    /// received from the user, while the `Error` in `.1` is the deserialization
    /// error from `serde`.
    Parse(&'a str, serde_json::error::Error),
}

impl<'r, T: Deserialize<'r>> JsonValidation<T> {
    fn from_str(s: &'r str) -> Result<Self, JsonValidationError<'r>> {
        serde_json::from_str(s)
            .map(JsonValidation)
            .map_err(|e| JsonValidationError::Parse(s, e))
    }

    async fn from_data(
        req: &'r Request<'_>,
        data: Data<'r>,
    ) -> Result<Self, JsonValidationError<'r>> {
        // TODO: Check max payload size for JSON
        let string = match data.open(ByteUnit::Mebibyte(10)).into_string().await {
            Ok(s) if s.is_complete() => s.into_inner(),
            Ok(_) => {
                let eof = io::ErrorKind::UnexpectedEof;
                return Err(JsonValidationError::Io(io::Error::new(
                    eof,
                    "data limit exceeded",
                )));
            }
            Err(e) => return Err(JsonValidationError::Io(e)),
        };

        Self::from_str(local_cache!(req, string))
    }
}

#[async_trait]
impl<'r, T: Deserialize<'r>> FromData<'r> for JsonValidation<T> {
    type Error = JsonValidationError<'r>;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        match Self::from_data(req, data).await {
            Ok(value) => Outcome::Success(value),
            Err(e) => {
                req.local_cache(|| <&JsonValidationError as Into<ApiError>>::into(&e));
                match e {
                    JsonValidationError::Io(_) => Outcome::Failure((Status::PayloadTooLarge, e)),
                    JsonValidationError::Parse(_, _) => {
                        req.local_cache(|| {
                            Some(<&JsonValidationError as Into<ApiError>>::into(&e))
                        });
                        Outcome::Failure((Status::BadRequest, e))
                    }
                }
            }
        }
    }
}

impl<T> Deref for JsonValidation<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}
