use std::{fmt::Display, pin::Pin};

use crate::database::dao::{DAOError, DBViolation};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::Stream;
use serde::Serialize;

pub type StreamResult<T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send>>;
pub type InternalIdentifier = String;
pub type GetScansIDError = GetScansError;
pub type GetScansIDResultsError = GetScansError;
pub type GetScansIDStatusError = GetScansError;
pub type DeleteScansIDError = PostScansIDError;
pub type AppResult<T> = Result<T, ApiError>;

#[derive(Clone, Default, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientHash([u8; 32]);

impl<T> From<T> for ClientHash
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(value);
        let hash = hasher.finalize();
        Self(hash.into())
    }
}

impl Display for ClientHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .fold(String::with_capacity(self.0.len() * 2), |mut a, x| {
                    a.push_str(&format!("{x:02x}"));
                    a
                })
        )
    }
}

#[derive(Default, Debug, Clone)]
pub enum ClientIdentifier {
    #[default]
    Unknown,
    Known(ClientHash),
}

#[derive(Debug, thiserror::Error)]
pub enum GetScansError {
    #[error("Not found.")]
    NotFound,
    #[error("Unexpected error occurred: {0}.")]
    External(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl GetScansError {
    pub fn from_external<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::External(Box::new(err))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PostScansError {
    #[error("ID ({0}) is already in use.")]
    DuplicateId(String),
    #[error("Unexpected error occurred: {0}.")]
    External(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(Debug, thiserror::Error)]
pub enum PostScansIDError {
    #[error("Already running.")]
    Running,
    #[error("Unexpected error occurred: {0}.")]
    External(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl PostScansIDError {
    pub fn from_external<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::External(Box::new(err))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetScansIDResultsIDError {
    #[error("Not found.")]
    NotFound,
    #[error("Unexpected error occurred: {0}.")]
    External(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl GetScansIDResultsIDError {
    pub fn from_external<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::External(Box::new(err))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetVTsError {
    #[error("Not yet available.")]
    NotYetAvailable,
    #[error("{0}")]
    External(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(Debug, Serialize)]
pub struct BadRequest {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl From<&serde_json::Error> for BadRequest {
    fn from(value: &serde_json::Error) -> Self {
        Self {
            line: value.line(),
            column: value.column(),
            message: value.to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Not found")]
    NotFound,
    #[error("Conflict")]
    Conflict(Option<String>),
    #[error("Service unavailable")]
    ServiceUnavailable,
    #[error("Bad request")]
    BadRequest(BadRequest),
    #[error("Bad request: {0}")]
    BadRequestMessage(String),
    #[error("Unexpected error occurred: {0}")]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            ApiError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ApiError::Conflict(None) => StatusCode::CONFLICT.into_response(),
            ApiError::Conflict(Some(message)) => {
                (StatusCode::CONFLICT, Json(message)).into_response()
            }
            ApiError::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            ApiError::BadRequest(body) => (StatusCode::BAD_REQUEST, Json(body)).into_response(),
            ApiError::BadRequestMessage(message) => {
                (StatusCode::BAD_REQUEST, Json(message)).into_response()
            }
            ApiError::Internal(error) => {
                tracing::warn!(error = %error, "Unexpected error occurred");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

impl From<&serde_json::Error> for ApiError {
    fn from(value: &serde_json::Error) -> Self {
        Self::BadRequest(value.into())
    }
}

impl From<GetScansError> for ApiError {
    fn from(value: GetScansError) -> Self {
        match value {
            GetScansError::NotFound => Self::NotFound,
            GetScansError::External(error) => Self::Internal(error),
        }
    }
}

impl From<PostScansError> for ApiError {
    fn from(value: PostScansError) -> Self {
        match value {
            PostScansError::DuplicateId(id) => {
                Self::Conflict(Some(format!("ID ({id}) is already in use.")))
            }
            PostScansError::External(error) => Self::Internal(error),
        }
    }
}

impl From<PostScansIDError> for ApiError {
    fn from(value: PostScansIDError) -> Self {
        match value {
            PostScansIDError::Running => Self::Conflict(None),
            PostScansIDError::External(error) => Self::Internal(error),
        }
    }
}

impl From<GetScansIDResultsIDError> for ApiError {
    fn from(value: GetScansIDResultsIDError) -> Self {
        match value {
            GetScansIDResultsIDError::NotFound => Self::NotFound,
            GetScansIDResultsIDError::External(error) => Self::Internal(error),
        }
    }
}

impl From<GetVTsError> for ApiError {
    fn from(value: GetVTsError) -> Self {
        match value {
            GetVTsError::NotYetAvailable => Self::ServiceUnavailable,
            GetVTsError::External(error) => Self::Internal(error),
        }
    }
}

pub(crate) fn map_post_scan_result<T>(
    result: Result<T, DAOError>,
    duplicate_id: String,
) -> Result<T, PostScansError> {
    match result {
        Ok(result) => Ok(result),
        Err(DAOError::DBViolation(DBViolation::UniqueViolation)) => {
            Err(PostScansError::DuplicateId(duplicate_id))
        }
        Err(error) => Err(PostScansError::External(Box::new(error))),
    }
}

pub(crate) fn map_contains_scan_id(
    result: Result<Option<InternalIdentifier>, DAOError>,
) -> Option<InternalIdentifier> {
    match result {
        Ok(x) => x,
        Err(error) => {
            tracing::warn!(%error, "Unable to fetch id from client_scan_map. Returning no id found.");
            None
        }
    }
}

pub(crate) fn into_get_scans_error(value: DAOError) -> GetScansError {
    match value {
        DAOError::NotFound => GetScansError::NotFound,
        error => GetScansError::External(Box::new(error)),
    }
}

pub(crate) fn map_result_id_fetch(
    result: Result<scannerlib::models::Result, DAOError>,
) -> Result<scannerlib::models::Result, GetScansIDResultsIDError> {
    result.map_err(|e| match e {
        DAOError::NotFound => GetScansIDResultsIDError::NotFound,
        e => GetScansIDResultsIDError::from_external(e),
    })
}
