use std::{
    pin::Pin,
    sync::{Arc, RwLock},
};

use futures::StreamExt;
use greenbone_scanner_framework::{
    GetVTsError, GetVts, entry::Prefixed, models, models::FeedState,
};
use sqlx::{Row, SqlitePool, query};

use crate::notus::advisories::VulnerabilityData;

pub struct VTEndpoints {
    pool: SqlitePool,
    feed_state: Arc<RwLock<FeedState>>,
    prefix: &'static str,
}
impl Prefixed for VTEndpoints {
    fn prefix(&self) -> &'static str {
        self.prefix
    }
}

impl VTEndpoints {
    pub fn new(
        pool: SqlitePool,
        feed_state: Arc<RwLock<FeedState>>,
        prefix: Option<&'static str>,
    ) -> Self {
        Self {
            pool,
            feed_state,
            prefix: prefix.unwrap_or(""),
        }
    }

    pub fn feed_state(&self) -> Pin<Box<dyn Future<Output = FeedState> + Send + 'static>> {
        let fs = self.feed_state.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let result = fs.read().unwrap();
                (*result).clone()
            })
            .await
            .unwrap()
        })
    }
}
fn error_vts_error<T>(error: T) -> GetVTsError
where
    T: std::error::Error + Sync + Send + 'static,
{
    GetVTsError::External(Box::new(error))
}

impl GetVts for VTEndpoints {
    fn get_oids(
        &self,
        _: String,
    ) -> greenbone_scanner_framework::StreamResult<
        'static,
        String,
        greenbone_scanner_framework::GetVTsError,
    > {
        let feed_state = self.feed_state.read().expect("Poison error");
        match &*feed_state {
            FeedState::Unknown | FeedState::Syncing => Box::new(futures::stream::iter(vec![Err(
                GetVTsError::NotYetAvailable,
            )])),
            FeedState::Synced(_, _) => {
                // we drop earlier as we  don't know how long the stream will be consumed
                drop(feed_state);
                let result = query("SELECT oid FROM plugins ORDER BY oid")
                    .fetch(&self.pool)
                    .map(|row| row.map(|e| e.get("oid")).map_err(error_vts_error));
                Box::new(result)
            }
        }
    }

    fn get_vts(
        &self,
        _: String,
    ) -> greenbone_scanner_framework::StreamResult<
        'static,
        models::VTData,
        greenbone_scanner_framework::GetVTsError,
    > {
        let feed_state = self.feed_state.read().expect("Poison error");
        match &*feed_state {
            FeedState::Unknown | FeedState::Syncing => Box::new(futures::stream::iter(vec![Err(
                GetVTsError::NotYetAvailable,
            )])),
            FeedState::Synced(_, _) => {
                // we drop earlier as we  don't know how long the stream will be consumed
                drop(feed_state);
                let result = query("SELECT feed_type, json_blob FROM plugins")
                    .fetch(&self.pool)
                    .map(|row| {
                        let r = row
                            .map(|x| match x.get("feed_type") {
                                "advisories" => {
                                    serde_json::from_slice::<VulnerabilityData>(x.get("json_blob"))
                                        .map_err(error_vts_error)
                                        .map(|x| x.into())
                                }
                                _ => serde_json::from_slice(x.get("json_blob"))
                                    .map_err(error_vts_error),
                            })
                            .map_err(error_vts_error);
                        match r {
                            Ok(Ok(x)) => Ok(x),
                            Ok(e) => e,
                            Err(e) => Err(e),
                        }
                    });

                Box::new(result)
            }
        }
    }
}
