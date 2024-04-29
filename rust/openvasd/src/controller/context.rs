// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::sync::RwLock;

use async_trait::async_trait;
use storage::DefaultDispatcher;

use crate::{config, notus::NotusWrapper, response, scheduling};

use models::scanner::{
    Error, ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper,
};

#[derive(Debug, Clone)]
pub struct NoScanner;
#[derive(Debug, Clone)]
pub struct Scanner<S>(S);

#[derive(Debug, Default)]
/// Context builder is used to build the context of the application.
pub struct ContextBuilder<S, DB, T> {
    scanner: T,
    storage: DB,
    feed_config: Option<crate::config::Feed>,
    api_key: Option<String>,
    enable_get_scans: bool,
    marker: std::marker::PhantomData<S>,
    response: response::Response,
    notus: Option<NotusWrapper>,
    scheduler_config: Option<config::Scheduler>,
    mode: config::Mode,
}

impl<S>
    ContextBuilder<S, crate::storage::inmemory::Storage<crate::crypt::ChaCha20Crypt>, NoScanner>
{
    /// Creates a new context builder.
    pub fn new() -> Self {
        Self {
            scanner: NoScanner,
            storage: crate::storage::inmemory::Storage::default(),
            feed_config: None,
            api_key: None,
            marker: std::marker::PhantomData,
            enable_get_scans: false,
            response: response::Response::default(),
            notus: None,
            scheduler_config: None,
            mode: config::Mode::default(),
        }
    }
}

impl<S, DB, T> ContextBuilder<S, DB, T> {
    /// Sets the mode.
    pub fn mode(mut self, mode: config::Mode) -> Self {
        self.mode = mode;
        self
    }
    /// Sets the feed config.
    pub fn feed_config(mut self, config: config::Feed) -> Self {
        self.feed_config = Some(config);
        if let Some(fp) = self.feed_config.as_ref() {
            let loader = nasl_interpreter::FSPluginLoader::new(fp.path.clone());
            let dispatcher: DefaultDispatcher<String> = DefaultDispatcher::default();
            let version =
                feed::version(&loader, &dispatcher).unwrap_or_else(|_| String::from("UNDEFINED"));
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

    /// Set notus
    pub fn notus(mut self, notus: NotusWrapper) -> Self {
        self.notus = Some(notus);
        self
    }

    pub fn scheduler_config(mut self, scheduler_config: config::Scheduler) -> Self {
        self.scheduler_config = Some(scheduler_config);
        self
    }

    /// Sets the storage.
    #[allow(dead_code)]
    pub fn storage<NDB>(self, storage: NDB) -> ContextBuilder<S, NDB, T> {
        let ContextBuilder {
            scanner,
            storage: _,
            feed_config,
            api_key,
            enable_get_scans,
            marker,
            response,
            notus,
            scheduler_config,
            mode,
        } = self;
        ContextBuilder {
            scanner,
            storage,
            feed_config,
            api_key,
            enable_get_scans,
            marker,
            response,
            notus,
            scheduler_config,
            mode,
        }
    }
}

impl<S, DB> ContextBuilder<S, DB, NoScanner> {
    /// Sets the scanner. This is required.
    pub fn scanner(self, scanner: S) -> ContextBuilder<S, DB, Scanner<S>>
    where
        S: models::scanner::Scanner
            + 'static
            + std::marker::Send
            + std::marker::Sync
            + std::fmt::Debug,
    {
        let Self {
            feed_config,
            api_key,
            enable_get_scans,
            scanner: _,
            marker: _,
            response,
            storage,
            notus,
            scheduler_config,
            mode,
        } = self;
        ContextBuilder {
            scanner: Scanner(scanner),
            storage,
            feed_config,
            marker: std::marker::PhantomData,
            api_key,
            enable_get_scans,
            response,
            notus,
            scheduler_config,
            mode,
        }
    }
}

impl<S, DB> ContextBuilder<S, DB, Scanner<S>> {
    pub fn build(self) -> Context<S, DB> {
        let scheduler = scheduling::Scheduler::new(
            self.scheduler_config.unwrap_or_default(),
            self.scanner.0,
            self.storage,
        );
        Context {
            response: self.response,
            scheduler,
            feed_config: self.feed_config,
            abort: Default::default(),
            api_key: self.api_key,
            enable_get_scans: self.enable_get_scans,
            notus: self.notus,
            mode: self.mode,
        }
    }
}

#[derive(Debug)]
/// The context of the application
pub struct Context<S, DB> {
    /// Creates responses
    pub response: response::Response,
    /// Configuration for feed handling.
    pub feed_config: Option<config::Feed>,
    /// The api key that is used to authenticate the client.
    ///
    /// When none api key is set, no authentication is required.
    pub api_key: Option<String>,
    /// Whether to enable the GET /scans endpoint
    pub enable_get_scans: bool,
    pub mode: config::Mode,
    /// Aborts the background loops
    pub abort: RwLock<bool>,
    /// Notus Scanner
    pub notus: Option<NotusWrapper>,
    /// All scanner and db operations must go through a scheduler.
    ///
    /// This allows us to throttle requests per need and gives us control when to start/stop/delete
    /// a scan.
    pub scheduler: scheduling::Scheduler<DB, S>,
}

#[derive(Debug, Clone, Default)]
/// A scanner without any side effects. Used for testing.
pub struct NoOpScanner;

#[async_trait]
impl ScanStarter for NoOpScanner {
    async fn start_scan(&self, _: models::Scan) -> Result<(), Error> {
        Ok(())
    }

    async fn can_start_scan(&self, _: &models::Scan) -> bool {
        true
    }
}

#[async_trait]
impl ScanStopper for NoOpScanner {
    async fn stop_scan<I>(&self, _: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send,
    {
        Ok(())
    }
}

#[async_trait]
impl ScanDeleter for NoOpScanner {
    async fn delete_scan<I>(&self, _: I) -> Result<(), Error>
    where
        I: AsRef<str> + Send,
    {
        Ok(())
    }
}

#[async_trait]
impl ScanResultFetcher for NoOpScanner {
    async fn fetch_results<I>(&self, _: I) -> Result<ScanResults, Error>
    where
        I: AsRef<str> + Send,
    {
        Ok(Default::default())
    }
}

impl Default
    for Context<NoOpScanner, crate::storage::inmemory::Storage<crate::crypt::ChaCha20Crypt>>
{
    fn default() -> Self {
        ContextBuilder::new().scanner(Default::default()).build()
    }
}
