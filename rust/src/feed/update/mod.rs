// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod error;

pub use error::Error;
pub use error::ErrorKind;

use futures::{stream, Stream, StreamExt};
use std::fs::File;
use tracing::trace;

use crate::nasl::interpreter::{CodeInterpreter, Interpreter};
use crate::nasl::nasl_std_functions;
use crate::nasl::prelude::*;
use crate::nasl::syntax::AsBufReader;
use crate::nasl::utils::context::Target;
use crate::nasl::utils::Executor;
use crate::nasl::ContextType;
use crate::storage::{item::NVTField, ContextKey, Dispatcher, NoOpRetriever};

use crate::feed::verify::check_signature;
use crate::feed::verify::{HashSumFileItem, SignatureChecker};

use super::verify;

/// Updates runs nasl plugin with description true and uses given storage to store the descriptive
/// information
pub struct Update<'a, S, L, V> {
    /// Is used to store data
    dispatcher: &'a S,
    /// Is used to load nasl plugins by a relative path
    loader: &'a L,
    /// Initial data, usually set in new.
    initial: Vec<(String, ContextType)>,
    /// How often loader or storage should retry before giving up when a retryable error occurs.
    max_retry: usize,
    verifier: V,
    feed_version_set: bool,
    executor: Executor,
}

/// Loads the plugin_feed_info and returns the feed version
pub async fn feed_version(
    loader: &dyn Loader,
    dispatcher: &dyn Dispatcher,
) -> Result<String, ErrorKind> {
    let feed_info_key = "plugin_feed_info.inc";
    let code = loader.load(feed_info_key)?;
    let register = Register::default();
    let k = ContextKey::default();
    let fr = NoOpRetriever::default();
    let target = Target::default();
    // TODO add parameter to struct
    let functions = nasl_std_functions();
    let context = Context::new(k, target, dispatcher, &fr, loader, &functions);
    let mut interpreter = Interpreter::new(register, &context);
    for stmt in crate::nasl::syntax::parse(&code) {
        let stmt = stmt?;
        interpreter.retry_resolve_next(&stmt, 3).await?;
    }

    let feed_version = interpreter
        .register()
        .named("PLUGIN_SET")
        .map(|x| x.to_string())
        .unwrap_or_else(|| "0".to_owned());
    Ok(feed_version)
}

impl<'a, S, L, V> SignatureChecker for Update<'a, S, L, V>
where
    S: Sync + Send + Dispatcher,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a>, verify::Error>>,
{
}

impl<'a, S, L, V> Update<'a, S, L, V>
where
    S: Sync + Send + Dispatcher,
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
            dispatcher: storage,
            verifier,
            feed_version_set: false,
            executor: nasl_std_functions(),
        }
    }

    /// Loads the plugin_feed_info and returns the feed version
    pub async fn feed_version(&self) -> Result<String, ErrorKind> {
        feed_version(self.loader, self.dispatcher).await
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
        self.dispatcher.retry_dispatch(
            self.max_retry,
            &Default::default(),
            NVTField::Version(feed_version).into(),
        )?;
        let feed_info_key = "plugin_feed_info.inc";
        Ok(feed_info_key.into())
    }

    /// Runs a single plugin in description mode.
    async fn single(&self, key: &ContextKey) -> Result<i64, ErrorKind> {
        let code = self.loader.load(&key.value())?;

        let register = Register::root_initial(&self.initial);
        let fr = NoOpRetriever::default();
        let target = Target::default();
        let context = Context::new(
            key.clone(),
            target,
            self.dispatcher,
            &fr,
            self.loader,
            &self.executor,
        );
        let mut results = Box::pin(CodeInterpreter::new(&code, register, &context).stream());
        while let Some(stmt) = results.next().await {
            match stmt {
                Ok(NaslValue::Exit(i)) => {
                    self.dispatcher.on_exit(context.key())?;
                    return Ok(i);
                }
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(ErrorKind::MissingExit(key.value()))
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
                let k = ContextKey::FileName(filename.clone());
                self.single(&k)
                    .await
                    .map(|_| k.value())
                    .map_err(|kind| Error {
                        kind,
                        key: k.value(),
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
