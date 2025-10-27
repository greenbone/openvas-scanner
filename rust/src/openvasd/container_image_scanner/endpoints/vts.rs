use std::sync::{Arc, RwLock};

use futures::StreamExt;
use greenbone_scanner_framework::{
    GetVTsError, GetVts, entry::Prefixed, models, models::FeedState,
};

use crate::vts::PluginFetcher;

pub struct VTEndpoints {
    fetcher: Box<dyn crate::vts::PluginFetcher + Send + Sync + 'static>,
    feed_state: Arc<RwLock<FeedState>>,
    prefix: &'static str,
}
impl Prefixed for VTEndpoints {
    fn prefix(&self) -> &'static str {
        self.prefix
    }
}

impl VTEndpoints {
    pub fn new<T>(
        fetcher: T,
        feed_state: Arc<RwLock<FeedState>>,
        prefix: Option<&'static str>,
    ) -> Self
    where
        T: PluginFetcher + Send + Sync + 'static,
    {
        Self {
            fetcher: Box::new(fetcher),
            feed_state,
            prefix: prefix.unwrap_or(""),
        }
    }
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
                drop(feed_state);
                Box::new(
                    self.fetcher
                        .get_oids()
                        .map(|x| x.map_err(|e| GetVTsError::External(Box::new(e)))),
                )
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
                Box::new(
                    self.fetcher
                        .get_vts()
                        .map(|x| x.map_err(|e| GetVTsError::External(Box::new(e)))),
                )
            }
        }
    }
}
