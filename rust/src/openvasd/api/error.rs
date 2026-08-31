//! Unified error handling within the API.
use std::error::Error;

use crate::{
    api::response::{BadRequest, BodyKind},
    database::dao::{DAOError, DBViolation},
    scans::scheduling,
    vts::orchestrator::WorkerError,
};

use axum::{
    body::Body,
    extract::rejection::JsonRejection,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use scannerlib::{models, notus::NotusError};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

/// Unified API error type.
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("database error: {0}")]
    Database(#[from] DAOError),
    #[error("notus error: {0}")]
    Notus(#[from] NotusError),
    #[error("scheduling error: {0}")]
    Scheduling(#[from] SendError<scheduling::Message>),
    #[error("duplicate credentials")]
    DuplicateCredentials(models::Service),
    #[error("feed is not synced")]
    FeedNotSynced,
    #[error("scan still running")]
    ScanRunning,
    #[error("json error: {0}")]
    Json(#[from] JsonRejection),
    #[error("invalid user input: {0}")]
    InvalidInput(String),
    #[error("failed to fetch VT: {0}")]
    VtsError(WorkerError),
}

impl ApiError {
    /// Transforms an ApiError into a HTTP StatusCode reflecting it's meaning.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Database(e) => match e {
                DAOError::DBViolation(_) => StatusCode::CONFLICT,
                DAOError::NotFound => StatusCode::NOT_FOUND,
                DAOError::Corrupt | DAOError::Infrastructure(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
            ApiError::Notus(e) => match e {
                NotusError::UnknownProduct(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            ApiError::Scheduling(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::DuplicateCredentials(_) => StatusCode::BAD_REQUEST,
            ApiError::FeedNotSynced => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::ScanRunning => StatusCode::CONFLICT,
            ApiError::Json(_) => StatusCode::BAD_REQUEST,
            ApiError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            ApiError::VtsError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// JSON encoded error representation
#[derive(Serialize)]
pub struct ErrorJson {
    status: u16,
    message: String,
    details: Option<String>,
}

impl From<ApiError> for ErrorJson {
    fn from(value: ApiError) -> Self {
        let status = value.status_code().as_u16();

        let (message, details) = match value {
            ApiError::Database(e) => match e {
                DAOError::DBViolation(DBViolation::UniqueViolation) => {
                    ("Scan ID already in use".to_string(), None)
                }
                DAOError::NotFound => ("Entry not found".to_string(), None),
                _ => ("Internal server error".to_string(), None),
            },
            ApiError::Notus(NotusError::UnknownProduct(product)) => {
                ("Unknown notus product".to_string(), Some(product))
            }
            ApiError::Scheduling(_) | ApiError::VtsError(_) | ApiError::Notus(_) => {
                ("Internal server error".to_string(), None)
            }
            ApiError::DuplicateCredentials(service) => (
                "Duplicate service credentials".to_string(),
                Some(service.to_string()),
            ),
            ApiError::FeedNotSynced => ("Feed is not synced".to_string(), None),
            ApiError::ScanRunning => (
                "Unable to perform action".to_string(),
                Some("Scan is already running".to_string()),
            ),
            ApiError::Json(err) => ("Failed to process JSON".to_string(), Some(err.to_string())),
            ApiError::InvalidInput(err) => ("Invalid query".to_string(), Some(err)),
        };

        Self {
            status,
            message,
            details,
        }
    }
}

/// Transforms an [`ApiError`] into an `HTTP` response.
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        tracing::warn!("{self}");

        let resp = Response::builder()
            .status(self.status_code())
            .header(CONTENT_TYPE, "application/json");

        let err_json: ErrorJson = self.into();
        resp.body(Body::from(
            serde_json::to_string(&err_json).expect("valid json"),
        ))
        .expect("valid response")
    }
}

impl From<ApiError> for BodyKind {
    fn from(value: ApiError) -> Self {
        match value {
            ApiError::Json(JsonRejection::JsonSyntaxError(err)) => {
                if let Some(e) = err.source()
                    && let Some(e) = e.downcast_ref::<serde_json::Error>()
                {
                    let br = BadRequest {
                        line: e.line(),
                        column: e.column(),
                        message: e.to_string(),
                    };

                    BodyKind::json_content(StatusCode::BAD_REQUEST, &br)
                } else {
                    BodyKind::no_content(StatusCode::BAD_REQUEST)
                }
            }
            _ => BodyKind::no_content(value.status_code()),
        }
    }
}
