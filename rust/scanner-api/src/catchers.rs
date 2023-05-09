use rocket::{catch, http::Status, Request};

use crate::error::ApiError;

fn json_parse_error(req: &Request, code: Status) -> ApiError {
    let validation_errors = req.local_cache::<Option<ApiError>, _>(|| None);
    match validation_errors {
        Some(e) => e.to_owned(),
        None => ApiError::Unexpected {
            message: format!(
                "The server caught a {}({}) with an unexpected error",
                code.code,
                code.reason().unwrap_or_default()
            ),
        },
    }
}

#[catch(400)]
pub fn json_bad_request(req: &Request) -> ApiError {
    json_parse_error(req, Status::BadRequest)
}

#[catch(422)]
pub fn json_unprocessable_entity(req: &Request) -> ApiError {
    json_parse_error(req, Status::UnprocessableEntity)
}

#[catch(401)]
pub fn unauthorized(req: &Request) -> ApiError {
    let e = req.local_cache::<Option<ApiError>, _>(|| None);
    match e {
        Some(e) => e.to_owned(),
        None => ApiError::Unexpected {
            message: "The server caught a 401(Unauthorized) with an unexpected error".to_string(),
        },
    }
}
