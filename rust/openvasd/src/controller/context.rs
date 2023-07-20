// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{collections::HashMap, path::PathBuf, sync::RwLock};


use storage::DefaultDispatcher;

use crate::{
    response,
    scan::{Error, ScanDeleter, ScanResultFetcher, ScanStarter, ScanStopper},
};

#[derive(Debug, Clone)]
pub struct NoScanner;
#[derive(Debug, Clone)]
pub struct Scanner<S>(S);

#[derive(Debug, Clone)]
/// sets the interval when to check for new results.
pub struct ResultContext(pub std::time::Duration);

impl From<std::time::Duration> for ResultContext {
    fn from(d: std::time::Duration) -> Self {
        Self(d)
    }
}

#[derive(Debug, Clone)]
/// Sets the path to the feed and the interval when to check for updates.
pub struct FeedContext {
    /// The path to the feed.
    pub path: PathBuf,
    /// The interval when to check for updates.
    pub verify_interval: std::time::Duration,
}

impl From<(PathBuf, std::time::Duration)> for FeedContext {
    fn from((path, verify_interval): (PathBuf, std::time::Duration)) -> Self {
        Self {
            path,
            verify_interval,
        }
    }
}

impl From<(&str, std::time::Duration)> for FeedContext {
    fn from((path, verify_interval): (&str, std::time::Duration)) -> Self {
        (PathBuf::from(path), verify_interval).into()
    }
}

#[derive(Debug, Clone, Default)]
/// Context builder is used to build the context of the application.
pub struct ContextBuilder<S, T> {
    scanner: T,
    result_config: Option<ResultContext>,
    feed_config: Option<FeedContext>,
    api_key: Option<String>,
    enable_get_scans: bool,
    marker: std::marker::PhantomData<S>,
    response: response::Response,
}

impl<S> ContextBuilder<S, NoScanner> {
    /// Creates a new context builder.
    pub fn new() -> Self {
        Self {
            scanner: NoScanner,
            result_config: None,
            feed_config: None,
            api_key: None,
            marker: std::marker::PhantomData,
            enable_get_scans: false,
            response: response::Response::default(),
        }
    }
}

impl<S, T> ContextBuilder<S, T> {
    /// Sets the result config.
    pub fn result_config(mut self, config: impl Into<ResultContext>) -> Self {
        self.result_config = Some(config.into());
        self
    }

    /// Sets the feed config.
    pub fn feed_config(mut self, config: impl Into<FeedContext>) -> Self {
        self.feed_config = Some(config.into());
        if let Some(fp) = self.feed_config.as_ref() {
            let loader = nasl_interpreter::FSPluginLoader::new(fp.path.clone());
            let dispatcher: DefaultDispatcher<String> = DefaultDispatcher::default();
            let version = feed::version(&loader, &dispatcher).unwrap();
            self.response.set_feed_version(&version);
        }
        self
    }

    /// Sets the api key.
    pub fn api_key(mut self, api_key: impl Into<Option<String>>) -> Self {
        self.api_key = api_key.into();
        if self.api_key.is_some() {
            self.response.add_authentication("x-api-key");
        }
        self
    }

    /// Enables the GET /scans endpoint.
    pub fn enable_get_scans(mut self, enable: bool) -> Self {
        self.enable_get_scans = enable;
        self
    }
}

impl<S> ContextBuilder<S, NoScanner>
where
    S: Clone + Send,
{
    /// Sets the scanner. This is required.
    pub fn scanner(self, scanner: S) -> ContextBuilder<S, Scanner<S>>
    where
        S: super::Scanner + 'static + std::marker::Send + std::marker::Sync + std::fmt::Debug,
    {
        let Self {
            result_config,
            feed_config,
            api_key,
            enable_get_scans,
            scanner: _,
            marker: _,
            response,
        } = self;
        ContextBuilder {
            scanner: Scanner(scanner),
            result_config,
            feed_config,
            marker: std::marker::PhantomData,
            api_key,
            enable_get_scans,
            response,
        }
    }
}

impl<S> ContextBuilder<S, Scanner<S>> {
    pub fn build(self) -> Context<S> {
        Context {
            scanner: self.scanner.0,
            response: self.response,
            scans: Default::default(),
            oids: Default::default(),
            result_config: self.result_config,
            feed_config: self.feed_config,
            abort: Default::default(),
            api_key: self.api_key,
            enable_get_scans: self.enable_get_scans,
        }
    }
}

#[derive(Debug)]
/// The context of the application
pub struct Context<S> {
    /// The scanner that is used to start, stop and fetch results of scans.
    pub scanner: S,
    /// Creates responses
    pub response: response::Response,
    /// The scans that are being tracked.
    ///
    /// It is locked to allow concurrent access, usually the results are updated
    /// with a background task and appended to the progress of the scan.
    pub scans: RwLock<HashMap<String, crate::scan::Progress>>,
    /// The OIDs thate can be handled by this sensor.
    pub oids: RwLock<(String, Vec<String>)>,
    /// Configuration for result fetching
    pub result_config: Option<ResultContext>,
    /// Configuration for feed handling.
    pub feed_config: Option<FeedContext>,
    /// The api key that is used to authenticate the client.
    ///
    /// When none api key is set, no authentication is required.
    pub api_key: Option<String>,
    /// Whether to enable the GET /scans endpoint
    pub enable_get_scans: bool,
    /// Aborts the background loops
    pub abort: RwLock<bool>,
}

#[derive(Debug, Clone, Default)]
/// A scanner without any side effects. Used for testing.
pub struct NoOpScanner;

impl ScanStarter for NoOpScanner {
    fn start_scan<'a>(&'a self, _: &'a crate::scan::Progress) -> Result<(), Error> {
        Ok(())
    }
}

impl ScanStopper for NoOpScanner {
    fn stop_scan(&self, _: &crate::scan::Progress) -> Result<(), Error> {
        Ok(())
    }
}

impl ScanDeleter for NoOpScanner {
    fn delete_scan(&self, _: &crate::scan::Progress) -> Result<(), Error> {
        Ok(())
    }
}

impl ScanResultFetcher for NoOpScanner {
    fn fetch_results(&self, _: &crate::scan::Progress) -> Result<crate::scan::FetchResult, Error> {
        Ok(Default::default())
    }
}

impl Default for Context<NoOpScanner> {
    fn default() -> Self {
        ContextBuilder::new().scanner(Default::default()).build()
    }
}
