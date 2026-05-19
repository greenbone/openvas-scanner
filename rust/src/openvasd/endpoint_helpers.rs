use std::future::Future;

use greenbone_scanner_framework::{InternalIdentifier, prelude::*};

use crate::database::dao::DAOError;

pub(crate) fn map_post_scan_result<T>(
    result: Result<T, DAOError>,
    duplicate_id: String,
) -> Result<T, PostScansError> {
    match result {
        Ok(result) => Ok(result),
        Err(DAOError::DBViolation(crate::database::dao::DBViolation::UniqueViolation)) => {
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

pub(crate) fn into_get_scans_error<T>(value: T) -> GetScansError
where
    T: std::error::Error + Send + Sync + 'static,
{
    GetScansError::External(Box::new(value))
}

pub(crate) fn map_result_id_fetch(
    result: Result<scannerlib::models::Result, DAOError>,
) -> Result<scannerlib::models::Result, GetScansIDResultsIDError> {
    result.map_err(|e| match e {
        DAOError::NotFound => GetScansIDResultsIDError::NotFound,
        e => e.into(),
    })
}

pub(crate) async fn delete_scan_if_not_running<PhaseFut, DeleteFut>(
    phase: PhaseFut,
    delete: DeleteFut,
) -> Result<(), DeleteScansIDError>
where
    PhaseFut: Future<Output = Result<scannerlib::models::Phase, DAOError>>,
    DeleteFut: Future<Output = Result<(), DAOError>>,
{
    let phase = phase.await.map_err(DeleteScansIDError::from_external)?;
    if phase.is_running() {
        return Err(DeleteScansIDError::Running);
    }
    delete.await.map_err(DeleteScansIDError::from_external)
}
