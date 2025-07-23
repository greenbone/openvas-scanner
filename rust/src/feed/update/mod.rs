// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod error;

pub use error::Error;
pub use error::ErrorKind;

use futures::{Stream, StreamExt, stream};
use std::fs::File;
use tracing::trace;

use crate::nasl::interpreter::ForkingInterpreter;
use crate::nasl::nasl_std_functions;
use crate::nasl::prelude::*;
use crate::nasl::syntax::AsBufReader;
use crate::nasl::utils::Executor;
use crate::nasl::utils::scan_ctx::ContextStorage;
use crate::nasl::utils::scan_ctx::Target;

use crate::feed::verify::check_signature;
use crate::feed::verify::{HashSumFileItem, SignatureChecker};
use crate::scanner::preferences::preference::ScanPrefs;
use crate::storage::ScanID;
use crate::storage::items::nvt::FeedVersion;
use crate::storage::items::nvt::FileName;

use super::verify;

/// Updates runs nasl plugin with description true and uses given storage to store the descriptive
/// information
pub struct Update<'a, S, L, V> {
    /// Is used to store data
    storage: &'a S,
    /// Is used to load nasl plugins by a relative path
    loader: &'a L,
    /// Initial data, usually set in new.
    initial: Vec<(String, NaslValue)>,
    /// How often loader or storage should retry before giving up when a retryable error occurs.
    max_retry: usize,
    verifier: V,
    feed_version_set: bool,
    executor: Executor,
}

/// Loads the plugin_feed_info and returns the feed version
pub async fn feed_version(
    loader: &dyn Loader,
    dispatcher: &dyn ContextStorage,
) -> Result<String, ErrorKind> {
    let feed_info_filename = "plugin_feed_info.inc";
    let code = Code::load(loader, feed_info_filename)?;
    let register = Register::default();
    let scan_id = ScanID("".to_string());
    let target = Target::localhost();
    let ports = Default::default();
    let filename = "";
    let executor = nasl_std_functions();
    let scan_params = ScanPrefs::new();
    let alive_test_methods = Vec::default();
    let cb = ScanCtxBuilder {
        storage: dispatcher,
        loader,
        executor: &executor,
        target,
        ports,
        filename,
        scan_id,
        scan_preferences: scan_params,
        alive_test_methods,
    };
    let context = cb.build();
    let mut interpreter = ForkingInterpreter::new(
        code.parse().emit_errors().map_err(ErrorKind::SyntaxError)?,
        register,
        &context,
    );
    interpreter.execute_all().await?;

    let feed_version = interpreter
        .register()
        .nasl_value("PLUGIN_SET")
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "0".to_owned());
    Ok(feed_version)
}

impl<'a, S, L, V> SignatureChecker for Update<'a, S, L, V>
where
    S: Sync + Send + ContextStorage,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a>, verify::Error>>,
{
}

impl<'a, S, L, V> Update<'a, S, L, V>
where
    S: Sync + Send + ContextStorage,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a>, verify::Error>> + 'a,
{
    /// Creates an updater. This updater is implemented as a iterator.
    ///
    /// It will iterate through the filenames retrieved by the verifier and execute each found
    /// `.nasl` script in description mode. When there is no filename left than it will handle the
    /// corresponding `plugin_feed_info.inc` to set the feed version. This is done after each file
    /// has run in description mode because some legacy systems consider a feed update done when
    /// the version is set.
    pub fn init(
        openvas_version: &str,
        max_retry: usize,
        loader: &'a L,
        storage: &'a S,
        verifier: V,
    ) -> Self {
        let initial = vec![
            ("description".to_owned(), true.into()),
            ("OPENVAS_VERSION".to_owned(), openvas_version.into()),
        ];
        Self {
            initial,
            max_retry,
            loader,
            storage,
            verifier,
            feed_version_set: false,
            executor: nasl_std_functions(),
        }
    }

    /// Loads the plugin_feed_info and returns the feed version
    async fn feed_version(&self) -> Result<String, ErrorKind> {
        feed_version(self.loader, self.storage).await
    }

    /// Check if the current feed is outdated.
    pub async fn feed_is_outdated(&self, current_version: String) -> Result<bool, ErrorKind> {
        // the version in file
        let v = self.feed_version().await?;
        if !current_version.is_empty() {
            return Ok(v.as_str() != current_version.as_str());
        };

        Ok(true)
    }

    /// plugin_feed_info must be handled differently.
    ///
    /// Usually a plugin_feed_info.inc is setup as a listing of keys.
    /// The feed_version is loaded from that inc file.
    /// Therefore we need to load the plugin_feed_info and extract the feed_version
    /// to put into the corresponding dispatcher.
    async fn dispatch_feed_info(&self) -> Result<String, ErrorKind> {
        let feed_version = self.feed_version().await?;
        self.storage
            .retry_dispatch(FeedVersion, feed_version, self.max_retry)?;

        let feed_info_key = "plugin_feed_info.inc";
        Ok(feed_info_key.into())
    }

    /// Runs a single plugin in description mode.
    async fn single(&self, key: &FileName) -> Result<i64, ErrorKind> {
        let code = Code::load(self.loader, &key.0)?;

        // Technically, we don't need to set the "description" variable
        // anymore, since the parse_description_block function returns
        // the statements from within the if.
        let register = Register::from_global_variables(&self.initial);
        let scan_params = ScanPrefs(Vec::default());
        let alive_test_methods = Vec::default();
        let target = Target::localhost();
        let ports = Default::default();
        let context = ScanCtxBuilder {
            scan_id: ScanID(key.0.clone()),
            target,
            ports,
            filename: &key.0,
            storage: self.storage,
            loader: self.loader,
            executor: &self.executor,
            scan_preferences: scan_params,
            alive_test_methods,
        };
        let context = context.build();
        let ast = code
            .parse_description_block()
            .emit_errors()
            .map_err(ErrorKind::SyntaxError)?;
        let mut results = Box::pin(ForkingInterpreter::new(ast, register, &context).stream());
        while let Some(stmt) = results.next().await {
            match stmt {
                Ok(NaslValue::Exit(i)) => {
                    return Ok(i);
                }
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(ErrorKind::MissingExit(key.0.clone()))
    }

    /// Perform a signature check of the sha256sums file
    pub fn verify_signature(&self) -> Result<(), verify::Error> {
        let path = self.loader.root_path().unwrap();
        check_signature(&path)
    }

    /// Run the feed update and log each result with the
    /// given log level. If an error occurs, return it.
    pub async fn perform_update(self) -> Result<(), Error> {
        let results = self.stream().collect::<Vec<_>>().await;
        for result in results.into_iter() {
            let result = result?;
            trace!(?result);
        }
        Ok(())
    }

    pub fn stream(self) -> impl Stream<Item = Result<String, Error>> + 'a {
        stream::unfold(self, |mut s| async move { s.next().await.map(|x| (x, s)) })
    }

    async fn next(&mut self) -> Option<Result<String, Error>> {
        match self.verifier.find(|x| {
            x.as_ref()
                .map(|x| x.get_filename().ends_with(".nasl"))
                .unwrap_or(true)
        }) {
            Some(Ok(k)) => {
                if let Err(e) = k.verify() {
                    return Some(Err(e.into()));
                }

                let mut filename = k.get_filename();
                if filename.starts_with("./") {
                    // sha256sums may start with ./ so we have to remove those as dependencies
                    // within nasl scripts usually don't entail them.
                    filename = filename[2..].to_string();
                }
                let k = FileName(filename.clone());
                self.single(&k)
                    .await
                    .map(|_| k.0.clone())
                    .map_err(|kind| Error {
                        kind,
                        key: k.0.clone(),
                    })
                    .into()
            }
            Some(Err(e)) => Some(Err(e.into())),
            None if !self.feed_version_set => {
                let result = self.dispatch_feed_info().await.map_err(|kind| Error {
                    kind,
                    key: "plugin_feed_info.inc".to_string(),
                });
                self.feed_version_set = true;
                Some(result)
            }
            None => None,
        }
    }
}
