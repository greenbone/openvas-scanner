// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::path::PathBuf;

use feed::HashSumNameLoader;
use nasl_interpreter::{
    load_non_utf8_path, logger::DefaultLogger, logger::NaslLogger, ContextBuilder, FSPluginLoader,
    Interpreter, KeyDispatcherSet, LoadError, Loader, NaslValue, NoOpLoader, RegisterBuilder,
};
use storage::{DefaultDispatcher, Dispatcher, Retriever};

use crate::{CliError, CliErrorKind, Db};

struct Run<K: AsRef<str>> {
    context_builder: nasl_interpreter::ContextBuilder<K, KeyDispatcherSet<K>>,
    feed: Option<PathBuf>,
}

impl Run<String> {
    fn new(db: &Db, feed: Option<PathBuf>, target: Option<String>) -> Self {
        let key = String::default();

        let mut context_builder = match db {
            Db::InMemory => ContextBuilder::new(key, Box::<DefaultDispatcher<String>>::default()),
            Db::Redis(url) => ContextBuilder::new(
                key,
                Box::new(redis_storage::NvtDispatcher::as_dispatcher(url).unwrap()),
            ),
        };

        context_builder = match feed.clone() {
            Some(x) => context_builder.loader(FSPluginLoader::new(x)),
            None => context_builder.loader(NoOpLoader::default()),
        }
        .target(target.unwrap_or_default());

        Self {
            context_builder,
            feed,
        }
    }

    fn load(&self, script: &str) -> Result<String, CliErrorKind> {
        match load_non_utf8_path(&script) {
            Ok(x) => Ok(x),
            Err(LoadError::NotFound(_)) => match self.feed.clone() {
                Some(f) => {
                    let loader = FSPluginLoader::new(f);
                    match HashSumNameLoader::sha256(&loader) {
                        Ok(hsnl) => {
                            let oid_filename =
                                feed::Oid::init(loader.clone(), hsnl).find(|x| match x {
                                    Ok((_, oid)) => oid == script, //self.loader.load(f).map_err(|e| e.into()),
                                    Err(_) => false,
                                });
                            match oid_filename {
                                Some(Ok((f, _))) => loader.load(&f).map_err(|e| e.into()),
                                Some(_) | None => {
                                    Err(LoadError::NotFound(script.to_string()).into())
                                }
                            }
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                None => Err(LoadError::NotFound(script.to_string()).into()),
            },
            Err(e) => Err(e.into()),
        }
    }

    fn run(&self, script: &str) -> Result<(), CliErrorKind> {
        let logger = DefaultLogger::default();
        let context = self.context_builder.build();
        let mut register = RegisterBuilder::build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let code = self.load(script)?;
        for stmt in nasl_syntax::parse(&code) {
            match stmt {
                Ok(stmt) => {
                    tracing::debug!("> {stmt}");
                    let r = match interpreter.retry_resolve(&stmt, 5) {
                        Ok(x) => x,
                        Err(e) => match &e.kind {
                            nasl_interpreter::InterpretErrorKind::FunctionCallError(
                                nasl_interpreter::FunctionError {
                                    function: _,
                                    kind: nasl_interpreter::FunctionErrorKind::Diagnostic(_, x),
                                },
                            ) => {
                                logger.warning(&e.to_string());
                                x.clone().unwrap_or_default()
                            }
                            _ => return Err(e.into()),
                        },
                    };
                    match r {
                        NaslValue::Exit(rc) => std::process::exit(rc as i32),
                        _ => {
                            tracing::debug!("=> {r:?}", r = r);
                        }
                    }
                }

                Err(e) => {
                    context.executor().nasl_fn_cache_clear();
                    return Err(e.into());
                }
            };
        }
        context.executor().nasl_fn_cache_clear();
        Ok(())
    }
}

trait Storage<K>: Dispatcher<K> + Retriever<K> {
    fn as_retriever(&self) -> &dyn Retriever<K>;
    fn as_dispatcher(&self) -> &dyn Dispatcher<K>;
}
impl<T, K> Storage<K> for T
where
    T: Dispatcher<K> + Retriever<K> + Sized,
{
    fn as_retriever(&self) -> &dyn Retriever<K> {
        self
    }

    fn as_dispatcher(&self) -> &dyn Dispatcher<K> {
        self
    }
}

pub fn run(
    db: &Db,
    feed: Option<PathBuf>,
    script: String,
    target: Option<String>,
) -> Result<(), CliError> {
    let runner = Run::new(db, feed, target);
    runner.run(&script).map_err(|e| CliError {
        filename: script,
        kind: e,
    })
}
