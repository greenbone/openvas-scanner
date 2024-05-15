// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod error;

pub use error::Error;

use std::{fmt::Display, fs::File, io::Read, marker::PhantomData};

use nasl_interpreter::{
    logger::DefaultLogger, AsBufReader, CodeInterpreter, Context, ContextType, Interpreter, Loader,
    NaslValue, Register,
};
use storage::{item::NVTField, Dispatcher, NoOpRetriever};

use crate::verify::{self, HashSumFileItem, SignatureChecker};

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
/// Loads the plugin_feed_info and returns the feed version
pub fn feed_version<K: Default + AsRef<str> + 'static>(
    loader: &dyn Loader,
    dispatcher: &dyn Dispatcher<K>,
) -> Result<String, ErrorKind> {
    let feed_info_key = "plugin_feed_info.inc";
    let code = loader.load(feed_info_key)?;
    let register = Register::default();
    let logger = DefaultLogger::default();
    let k: K = Default::default();
    let fr = NoOpRetriever::default();
    let target = String::default();
    // TODO add parameter to struct
    let functions = nasl_interpreter::nasl_std_functions();
    let context = Context::new(&k, &target, dispatcher, &fr, loader, &logger, &functions);
    let mut interpreter = Interpreter::new(register, &context);
    for stmt in nasl_syntax::parse(&code) {
        match stmt {
            Ok(stmt) => interpreter.retry_resolve_next(&stmt, 3)?,
            Err(e) => return Err(e.into()),
        };
    }

    let feed_version = interpreter
        .register()
        .named("PLUGIN_SET")
        .map(|x| x.to_string())
        .unwrap_or_else(|| "0".to_owned());
    Ok(feed_version)
}

impl<'a, R, S, L, V, K> SignatureChecker for Update<S, L, V, K>
where
    S: Sync + Send + Dispatcher<K>,
    K: AsRef<str> + Display + Default + From<String>,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a, R>, verify::Error>>,
    R: Read + 'a,
{
}

impl<'a, S, L, V, K, R> Update<S, L, V, K>
where
    S: Sync + Send + Dispatcher<K>,
    K: AsRef<str> + Display + Default + From<String> + 'static,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a, R>, verify::Error>>,
    R: Read + 'a,
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
            phanton: PhantomData,
        }
    }

    /// Loads the plugin_feed_info and returns the feed version
    pub fn feed_version(&self) -> Result<String, ErrorKind> {
        feed_version(&self.loader, &self.dispatcher)
    }

    /// plugin_feed_info must be handled differently.
    ///
    /// Usually a plugin_feed_info.inc is setup as a listing of keys.
    /// The feed_version is loaded from that inc file.
    /// Therefore we need to load the plugin_feed_info and extract the feed_version
    /// to put into the corresponding dispatcher.
    fn dispatch_feed_info(&self) -> Result<String, ErrorKind> {
        let feed_version = self.feed_version()?;
        self.dispatcher.retry_dispatch(
            self.max_retry,
            &Default::default(),
            NVTField::Version(feed_version).into(),
        )?;
        let feed_info_key = "plugin_feed_info.inc";
        Ok(feed_info_key.into())
    }

    /// Runs a single plugin in description mode.
    fn single(&self, key: &K) -> Result<i64, ErrorKind> {
        let code = self.loader.load(key.as_ref())?;

        let register = Register::root_initial(&self.initial);
        let logger = DefaultLogger::default();
        let fr = NoOpRetriever::default();
        let target = String::default();
        // TODO add parameter to struct
        let functions = nasl_interpreter::nasl_std_functions();

        let context = Context::new(
            key,
            &target,
            &self.dispatcher,
            &fr,
            &self.loader,
            &logger,
            &functions,
        );
        let interpreter = CodeInterpreter::new(&code, register, &context);
        for stmt in interpreter {
            match stmt {
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
    /// Perform a signature check of the sha256sums file
    pub fn verify_signature(&self) -> Result<(), verify::Error> {
        //self::SignatureChecker::signature_check(&path)
        let path = self.loader.root_path().unwrap();
        crate::verify::check_signature(&path)
    }
}

impl<'a, S, L, V, K, R> Iterator for Update<S, L, V, K>
where
    S: Sync + Send + Dispatcher<K>,
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a, R>, verify::Error>>,
    R: Read + 'a,
    K: AsRef<str> + Display + Default + From<String> + 'static,
{
    type Item = Result<String, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.verifier.find(|x| {
            if let Ok(x) = x {
                x.get_filename().ends_with(".nasl")
            } else {
                true
            }
        }) {
            Some(Ok(k)) => {
                if let Err(e) = k.verify() {
                    return Some(Err(e.into()));
                }
                let k: K = k.get_filename().into();
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
                let result = self.dispatch_feed_info().map_err(|kind| Error {
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
