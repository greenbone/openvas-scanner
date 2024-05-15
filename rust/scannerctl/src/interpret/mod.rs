// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::PathBuf;

use feed::HashSumNameLoader;
use nasl_interpreter::{
    load_non_utf8_path, CodeInterpreter, ContextBuilder, FSPluginLoader, KeyDispatcherSet,
    LoadError, Loader, NaslValue, NoOpLoader, RegisterBuilder,
};
use redis_storage::FEEDUPDATE_SELECTOR;
use storage::DefaultDispatcher;

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
                Box::new(
                    redis_storage::CacheDispatcher::as_dispatcher(url, FEEDUPDATE_SELECTOR)
                        .unwrap(),
                ),
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
        let context = self.context_builder.build();
        let register = RegisterBuilder::build();
        let code = self.load(script)?;
        let interpreter =
            CodeInterpreter::with_statement_callback(&code, register, &context, &|x| {
                tracing::debug!("> {x}")
            });
        for result in interpreter {
            let r = match result {
                Ok(x) => x,
                Err(e) => match &e.kind {
                    nasl_interpreter::InterpretErrorKind::FunctionCallError(
                        nasl_interpreter::FunctionError {
                            function: _,
                            kind: nasl_interpreter::FunctionErrorKind::Diagnostic(_, x),
                        },
                    ) => {
                        tracing::warn!(error=?e, "function call error");
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

        context.executor().nasl_fn_cache_clear();
        Ok(())
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
