use std::sync::{Arc, RwLock};

use crate::framework::{AppResult, ClientIdentifier, GetVTsError, StreamResult};
use axum::{
    Extension, Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use futures::{StreamExt, TryStreamExt};
use scannerlib::models::{self, FeedState};
use serde::Deserialize;

use crate::{
    app::AppState,
    config::ScannerType,
    database::sqlite::vts::SqlPluginStorage,
    vts::{PluginFetcher, redis::RedisPluginHandler},
};

pub struct VTEndpoints {
    pub fetcher: Box<dyn crate::vts::PluginFetcher + Send + Sync + 'static>,
    pub feed_state: Arc<RwLock<FeedState>>,
}

#[derive(Debug, Default, Deserialize)]
struct VTQuery {
    information: Option<String>,
}

impl VTQuery {
    fn detailed(&self) -> bool {
        matches!(self.information.as_deref(), Some("true" | "1"))
    }
}

impl VTEndpoints {
    pub fn from_appstate(app_state: &AppState<'_>) -> Arc<Self> {
        let fetcher: Box<dyn PluginFetcher + Send + Sync + 'static> =
            match app_state.config.scanner.scanner_type {
                ScannerType::Openvas => Box::new(RedisPluginHandler::from(app_state.config)),
                ScannerType::Openvasd | ScannerType::Ospd => {
                    Box::new(SqlPluginStorage::from(app_state.scan_state.pool()))
                }
            };

        Arc::new(Self {
            fetcher,
            feed_state: app_state.feed_state.clone(),
        })
    }

    fn client_id(ident: &ClientIdentifier) -> String {
        match ident {
            ClientIdentifier::Unknown => "unknown".to_string(),
            ClientIdentifier::Known(client_hash) => client_hash.to_string(),
        }
    }

    async fn get_vts_response(
        &self,
        ident: ClientIdentifier,
        query: VTQuery,
    ) -> AppResult<Response> {
        let client_id = Self::client_id(&ident);

        if query.detailed() {
            let vts = self.get_vts(client_id).try_collect::<Vec<_>>().await?;
            Ok((StatusCode::OK, Json(vts)).into_response())
        } else {
            let oids = self.get_oids(client_id).try_collect::<Vec<_>>().await?;
            Ok((StatusCode::OK, Json(oids)).into_response())
        }
    }

    fn routes(self: Arc<Self>) -> Router {
        Router::new().route(
            "/vts",
            get({
                let vts = self.clone();
                move |Extension(ident): Extension<ClientIdentifier>,
                      axum::extract::Query(query): axum::extract::Query<VTQuery>| async move {
                    vts.get_vts_response(ident, query).await
                }
            }),
        )
    }

    pub fn router(self: Arc<Self>, prefix: &'static str) -> Router {
        let router = self.routes();

        if prefix.is_empty() {
            router
        } else {
            Router::new().nest(prefix, router)
        }
    }

    pub fn get_oids(&self, _: String) -> StreamResult<String, GetVTsError> {
        let feed_state = self.feed_state.read().expect("Poison error");
        match &*feed_state {
            FeedState::Unknown | FeedState::Syncing => Box::pin(futures::stream::iter(vec![Err(
                GetVTsError::NotYetAvailable,
            )])),
            FeedState::Synced(_, _) => {
                drop(feed_state);
                Box::pin(
                    self.fetcher
                        .get_oids()
                        .map(|x| x.map_err(|e| GetVTsError::External(Box::new(e)))),
                )
            }
        }
    }

    pub fn get_vts(&self, _: String) -> StreamResult<models::VTData, GetVTsError> {
        let feed_state = self.feed_state.read().expect("Poison error");
        match &*feed_state {
            FeedState::Unknown | FeedState::Syncing => Box::pin(futures::stream::iter(vec![Err(
                GetVTsError::NotYetAvailable,
            )])),
            FeedState::Synced(_, _) => {
                // we drop earlier as we  don't know how long the stream will be consumed
                drop(feed_state);
                Box::pin(
                    self.fetcher
                        .get_vts()
                        .map(|x| x.map_err(|e| GetVTsError::External(Box::new(e)))),
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, RwLock};

    use crate::framework::{ClientHash, ClientIdentifier, StreamResult};
    use axum::{Extension, Router, body::Body, http::Request};
    use futures::stream;
    use scannerlib::models::VTData;
    use tower::ServiceExt;

    use super::*;
    use crate::vts::orchestrator::WorkerError;

    struct FakeFetcher {
        oids: Vec<String>,
        vts: Vec<VTData>,
        fail: bool,
    }

    impl PluginFetcher for FakeFetcher {
        fn get_oids(&self) -> StreamResult<String, WorkerError> {
            if self.fail {
                Box::pin(stream::iter(vec![Err(WorkerError::Send)]))
            } else {
                Box::pin(stream::iter(self.oids.clone().into_iter().map(Ok)))
            }
        }

        fn get_vts(&self) -> StreamResult<VTData, WorkerError> {
            if self.fail {
                Box::pin(stream::iter(vec![Err(WorkerError::Send)]))
            } else {
                Box::pin(stream::iter(self.vts.clone().into_iter().map(Ok)))
            }
        }
    }

    fn endpoint(
        fetcher: FakeFetcher,
        feed_state: FeedState,
        _prefix: Option<&'static str>,
    ) -> Arc<VTEndpoints> {
        Arc::new(VTEndpoints {
            fetcher: Box::new(fetcher),
            feed_state: Arc::new(RwLock::new(feed_state)),
        })
    }

    fn router(endpoint: Arc<VTEndpoints>, ident: ClientIdentifier, prefix: &'static str) -> Router {
        endpoint.router(prefix).layer(Extension(ident))
    }

    async fn send(router: &Router, request: Request<Body>) -> axum::response::Response {
        router.clone().oneshot(request).await.unwrap()
    }

    async fn body_json<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn returns_service_unavailable_while_feed_is_not_synced() {
        for state in [FeedState::Unknown, FeedState::Syncing] {
            let app = router(
                endpoint(
                    FakeFetcher {
                        oids: vec!["1.3.6.1.4.1".into()],
                        vts: vec![VTData {
                            oid: "1.3.6.1.4.1".into(),
                            ..VTData::default()
                        }],
                        fail: false,
                    },
                    state,
                    None,
                ),
                ClientIdentifier::Unknown,
                "",
            );

            let response = send(&app, Request::get("/vts").body(Body::empty()).unwrap()).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[tokio::test]
    async fn returns_oids_by_default() {
        let app = router(
            endpoint(
                FakeFetcher {
                    oids: vec!["1.3.6.1.4.1".into()],
                    vts: vec![VTData {
                        oid: "1.3.6.1.4.1".into(),
                        ..VTData::default()
                    }],
                    fail: false,
                },
                FeedState::Synced("nasl".into(), "notus".into()),
                None,
            ),
            ClientIdentifier::Known(ClientHash::from("ok")),
            "",
        );

        let response = send(&app, Request::get("/vts").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Vec<String> = body_json(response).await;
        assert_eq!(body, vec!["1.3.6.1.4.1"]);
    }

    #[tokio::test]
    async fn returns_detailed_vts_when_information_is_requested() {
        let app = router(
            endpoint(
                FakeFetcher {
                    oids: vec!["1.3.6.1.4.1".into()],
                    vts: vec![VTData {
                        oid: "1.3.6.1.4.1".into(),
                        ..VTData::default()
                    }],
                    fail: false,
                },
                FeedState::Synced("nasl".into(), "notus".into()),
                None,
            ),
            ClientIdentifier::Unknown,
            "",
        );

        for suffix in ["true", "1"] {
            let response = send(
                &app,
                Request::get(format!("/vts?information={suffix}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body: Vec<VTData> = body_json(response).await;
            assert_eq!(body.len(), 1);
            assert_eq!(body[0].oid, "1.3.6.1.4.1");
        }
    }

    #[tokio::test]
    async fn nests_routes_below_prefix() {
        let app = router(
            endpoint(
                FakeFetcher {
                    oids: vec!["1.3.6.1.4.1".into()],
                    vts: vec![VTData::default()],
                    fail: false,
                },
                FeedState::Synced("nasl".into(), "notus".into()),
                None,
            ),
            ClientIdentifier::Unknown,
            "/container-image-scanner",
        );

        let response = send(
            &app,
            Request::get("/container-image-scanner/vts")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
