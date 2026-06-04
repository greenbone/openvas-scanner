use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use scannerlib::{PromiseRef, models};
use serde::Deserialize;

use crate::framework::{
    ApiError, AppResult, ClientIdentifier, GetScansError, GetScansIDResultsIDError, PostScansError,
    PostScansIDError, StreamResult, stream_json_array_response,
};

#[derive(Clone)]
pub(crate) struct ScanRoutes<S> {
    scans: S,
    prefix: &'static str,
}

#[derive(Debug, Default, Deserialize)]
struct ResultsQuery {
    range: Option<String>,
}

pub(crate) trait ScanBackend: Clone + Send + Sync + 'static {
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> PromiseRef<'_, Result<String, PostScansError>>;

    fn contains_scan_id<'a>(
        &'a self,
        client_id: &'a str,
        scan_id: &'a str,
    ) -> PromiseRef<'a, Option<String>>;

    fn get_scans(&self, client_id: String) -> StreamResult<String, GetScansError>;

    fn get_scans_preferences(&self) -> PromiseRef<'_, Vec<models::ScanPreferenceInformation>>;

    fn get_scans_id(&self, id: String) -> PromiseRef<'_, Result<models::Scan, GetScansError>>;

    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<models::Result, GetScansError>;

    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> PromiseRef<'_, Result<models::Result, GetScansIDResultsIDError>>;

    fn get_scans_id_status(
        &self,
        id: String,
    ) -> PromiseRef<'_, Result<models::Status, GetScansError>>;

    fn post_scans_id(
        &self,
        id: String,
        action: models::Action,
    ) -> PromiseRef<'_, Result<(), PostScansIDError>>;

    fn delete_scans_id(&self, id: String) -> PromiseRef<'_, Result<(), PostScansIDError>>;
}

impl<S> ScanRoutes<S>
where
    S: ScanBackend,
{
    pub(crate) fn new(scans: S, prefix: &'static str) -> Self {
        Self { scans, prefix }
    }

    fn client_id(ident: &ClientIdentifier) -> Option<String> {
        match ident {
            ClientIdentifier::Known(client_hash) => Some(client_hash.to_string()),
            ClientIdentifier::Unknown => None,
        }
    }

    async fn authorized_scan_id(
        &self,
        ident: &ClientIdentifier,
        scan_id: String,
    ) -> AppResult<String> {
        let Some(client_id) = Self::client_id(ident) else {
            return Err(ApiError::Unauthorized);
        };

        self.scans
            .contains_scan_id(&client_id, &scan_id)
            .await
            .ok_or(ApiError::NotFound)
    }

    fn parse_range(query: ResultsQuery) -> (Option<usize>, Option<usize>) {
        query
            .range
            .as_deref()
            .map(|range| {
                let mut parts = range.splitn(2, '-');
                let from = parts.next().and_then(|v| v.parse().ok());
                let to = parts.next().and_then(|v| v.parse().ok());
                (from, to)
            })
            .unwrap_or((None, None))
    }

    async fn get_scans_response(&self, ident: ClientIdentifier) -> AppResult<Response> {
        let client_id = Self::client_id(&ident).ok_or(ApiError::Unauthorized)?;
        stream_json_array_response(self.scans.get_scans(client_id)).await
    }

    async fn post_scans_response(
        &self,
        ident: ClientIdentifier,
        body: Bytes,
    ) -> AppResult<Response> {
        let client_id = Self::client_id(&ident).ok_or(ApiError::Unauthorized)?;
        let mut scan =
            serde_json::from_slice::<models::Scan>(&body).map_err(|e| ApiError::from(&e))?;
        if scan.scan_id.is_empty() {
            scan.scan_id = uuid::Uuid::new_v4().into();
        }

        let id = self.scans.post_scans(client_id, scan).await?;
        Ok((StatusCode::CREATED, Json(id)).into_response())
    }

    async fn get_scan_response(
        &self,
        ident: ClientIdentifier,
        scan_id: String,
    ) -> AppResult<Response> {
        let scan_id = self.authorized_scan_id(&ident, scan_id).await?;
        let mut scan = self.scans.get_scans_id(scan_id).await?;
        scan.target.credentials = scan
            .target
            .credentials
            .into_iter()
            .map(|credential| credential.hide_pass())
            .collect();
        Ok((StatusCode::OK, Json(scan)).into_response())
    }

    async fn post_scan_action_response(
        &self,
        ident: ClientIdentifier,
        scan_id: String,
        body: Bytes,
    ) -> AppResult<Response> {
        let scan_id = self.authorized_scan_id(&ident, scan_id).await?;
        let action =
            serde_json::from_slice::<models::ScanAction>(&body).map_err(|e| ApiError::from(&e))?;
        self.scans.post_scans_id(scan_id, action.action).await?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    async fn delete_scan_response(
        &self,
        ident: ClientIdentifier,
        scan_id: String,
    ) -> AppResult<Response> {
        let scan_id = self.authorized_scan_id(&ident, scan_id).await?;
        self.scans.delete_scans_id(scan_id).await?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    async fn get_scan_status_response(
        &self,
        ident: ClientIdentifier,
        scan_id: String,
    ) -> AppResult<Response> {
        let scan_id = self.authorized_scan_id(&ident, scan_id).await?;
        let status = self.scans.get_scans_id_status(scan_id).await?;
        Ok((StatusCode::OK, Json(status)).into_response())
    }

    async fn get_scan_results_response(
        &self,
        ident: ClientIdentifier,
        scan_id: String,
        query: ResultsQuery,
    ) -> AppResult<Response> {
        let scan_id = self.authorized_scan_id(&ident, scan_id).await?;
        let (from, to) = Self::parse_range(query);
        stream_json_array_response(self.scans.get_scans_id_results(scan_id, from, to)).await
    }

    async fn get_scan_result_response(
        &self,
        ident: ClientIdentifier,
        scan_id: String,
        result_id: String,
    ) -> AppResult<Response> {
        let scan_id = self.authorized_scan_id(&ident, scan_id).await?;
        let result_id = result_id.parse::<usize>().map_err(|_| {
            ApiError::BadRequestMessage("result_id must be a positive number.".to_string())
        })?;
        let result = self
            .scans
            .get_scans_id_results_id(scan_id, result_id)
            .await?;
        Ok((StatusCode::OK, Json(result)).into_response())
    }

    async fn get_scan_preferences_response(&self, ident: ClientIdentifier) -> AppResult<Response> {
        Self::client_id(&ident).ok_or(ApiError::Unauthorized)?;
        let preferences = self.scans.get_scans_preferences().await;
        Ok((StatusCode::OK, Json(preferences)).into_response())
    }

    fn routes(&self) -> Router {
        Router::new()
            .route(
                "/scans",
                get({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>| async move {
                        scans.get_scans_response(ident).await
                    }
                })
                .post({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>, body: Bytes| async move {
                        scans.post_scans_response(ident, body).await
                    }
                }),
            )
            .route(
                "/scans/preferences",
                get({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>| async move {
                        scans.get_scan_preferences_response(ident).await
                    }
                }),
            )
            .route(
                "/scans/{scan_id}",
                get({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>,
                          Path(scan_id): Path<String>| async move {
                        scans.get_scan_response(ident, scan_id).await
                    }
                })
                .post({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>,
                          Path(scan_id): Path<String>,
                          body: Bytes| async move {
                        scans.post_scan_action_response(ident, scan_id, body).await
                    }
                })
                .delete({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>,
                          Path(scan_id): Path<String>| async move {
                        scans.delete_scan_response(ident, scan_id).await
                    }
                }),
            )
            .route(
                "/scans/{scan_id}/status",
                get({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>,
                          Path(scan_id): Path<String>| async move {
                        scans.get_scan_status_response(ident, scan_id).await
                    }
                }),
            )
            .route(
                "/scans/{scan_id}/results",
                get({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>,
                          Path(scan_id): Path<String>,
                          Query(query): Query<ResultsQuery>| async move {
                        scans.get_scan_results_response(ident, scan_id, query).await
                    }
                }),
            )
            .route(
                "/scans/{scan_id}/results/{result_id}",
                get({
                    let scans = self.clone();
                    move |Extension(ident): Extension<ClientIdentifier>,
                          Path((scan_id, result_id)): Path<(String, String)>| async move {
                        scans
                            .get_scan_result_response(ident, scan_id, result_id)
                            .await
                    }
                }),
            )
    }

    pub(crate) fn router(&self) -> Router {
        let router = self.routes();
        if self.prefix.is_empty() {
            router
        } else {
            Router::new().nest(self.prefix, router)
        }
    }
}
