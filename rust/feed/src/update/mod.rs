// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later
mod error;

pub use error::Error;

use std::{fmt::Display, fs::File, marker::PhantomData};

use nasl_interpreter::{
    AsBufReader, Context, ContextType, DefaultLogger, Interpreter, Loader, NaslValue, Register,
    Sessions,
};
use storage::{nvt::NVTField, Dispatcher, NoOpRetriever};

use crate::verify;

pub use self::error::ErrorKind;

/// Updates runs nasl plugin with description true and uses given storage to store the descriptive
/// information
pub struct Update<S, L, V, K> {
    /// Is used to store data
    dispatcher: S,
    /// Is used to load nasl plugins by a relative path
    loader: L,
    /// Initial data, usually set in new.
    initial: Vec<(String, ContextType)>,
    /// How often loader or storage should retry before giving up when a retryable error occurs.
    max_retry: usize,
    verifier: V,
    feed_version_set: bool,
    phanton: PhantomData<K>,
}

impl From<verify::Error> for ErrorKind {
    fn from(value: verify::Error) -> Self {
        ErrorKind::VerifyError(value)
    }
}

impl<S, L, V, K> Update<S, L, V, K>
where
    S: Sync + Send + Dispatcher<K>,
    K: AsRef<str> + Display + Default + From<String>,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<String, verify::Error>>,
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
        loader: L,
        storage: S,
        verifier: V,
    ) -> impl Iterator<Item = Result<String, Error>> {
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
            phanton: PhantomData,
        }
    }

    /// plugin_feed_info must be handled differently.
    ///
    /// Usually a plugin_feed_info.inc is setup as a listing of keys.
    /// The feed_version is loaded from that inc file.
    /// Therefore we need to load the plugin_feed_info and extract the feed_version
    /// to put into the corresponding dispatcher.
    fn plugin_feed_info(&self) -> Result<String, ErrorKind> {
        let feed_info_key = "plugin_feed_info.inc";
        let code = self.loader.load(feed_info_key)?;
        let mut register = Register::default();
        let logger = DefaultLogger::default();
        let sessions = Sessions::default();
        let k: K = Default::default();
        let fr = NoOpRetriever::default();
        let context = Context::new(&k, &self.dispatcher, &fr, &self.loader, &logger, &sessions);
        let mut interpreter = Interpreter::new(&mut register, &context);
        for stmt in nasl_syntax::parse(&code) {
            match stmt {
                Ok(stmt) => interpreter.retry_resolve(&stmt, self.max_retry)?,
                Err(e) => return Err(e.into()),
            };
        }

        let feed_version = register
            .named("PLUGIN_SET")
            .map(|x| x.to_string())
            .unwrap_or_else(|| "0".to_owned());
        self.dispatcher.retry_dispatch(
            self.max_retry,
            &k,
            NVTField::Version(feed_version).into(),
        )?;
        Ok(feed_info_key.into())
    }

    /// Runs a single plugin in description mode.
    fn single(&self, key: &K) -> Result<i64, ErrorKind> {
        let code = self.loader.load(key.as_ref())?;

        let mut register = Register::root_initial(&self.initial);
        let logger = DefaultLogger::default();
        let sessions = Sessions::default();
        let fr = NoOpRetriever::default();
        let context = Context::new(key, &self.dispatcher, &fr, &self.loader, &logger, &sessions);
        let mut interpreter = Interpreter::new(&mut register, &context);
        for stmt in nasl_syntax::parse(&code) {
            match interpreter.retry_resolve(&stmt?, self.max_retry) {
                Ok(NaslValue::Exit(i)) => {
                    self.dispatcher.on_exit()?;
                    return Ok(i);
                }
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(ErrorKind::MissingExit(key.as_ref().into()))
    }
}

impl<S, L, V, K> Iterator for Update<S, L, V, K>
where
    S: Sync + Send + Dispatcher<K>,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<String, verify::Error>>,
    K: AsRef<str> + Display + Default + From<String>,
{
    type Item = Result<String, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.verifier.find(|x| {
            if let Ok(x) = x {
                x.ends_with(".nasl")
            } else {
                true
            }
        }) {
            Some(Ok(k)) => {
                let k: K = k.into();
                self.single(&k)
                    .map(|_| k.as_ref().into())
                    .map_err(|kind| Error {
                        kind,
                        key: k.to_string(),
                    })
                    .into()
            }
            Some(Err(e)) => Some(Err(e.into())),
            None if !self.feed_version_set => {
                let result = self.plugin_feed_info().map_err(|kind| Error {
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
