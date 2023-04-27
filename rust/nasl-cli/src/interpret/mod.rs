// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fmt::Display, path::PathBuf};

use feed::HashSumNameLoader;
use nasl_interpreter::{
    load_non_utf8_path, Context, DefaultLogger, FSPluginLoader, Interpreter, LoadError, Loader,
    NaslLogger, NaslValue, NoOpLoader, Register, Sessions,
};
use storage::{DefaultDispatcher, Dispatcher, Retriever};

use crate::{CliError, CliErrorKind, Db};

struct Run<'a, K> {
    feed: Option<PathBuf>,
    dispatcher: &'a dyn Dispatcher<K>,
    retriever: &'a dyn Retriever<K>,
    key: K,
    loader: &'a dyn Loader,
}

impl<'a, K> Run<'a, K>
where
    K: AsRef<str>,
{
    fn new(
        key: K,
        feed: Option<PathBuf>,
        dispatcher: &'a dyn Dispatcher<K>,
        retriever: &'a dyn Retriever<K>,
        loader: &'a dyn Loader,
    ) -> Self {
        Self {
            feed,
            dispatcher,
            retriever,
            key,
            loader,
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
                        Err(_) => todo!(),
                    }
                }
                None => Err(LoadError::NotFound(script.to_string()).into()),
            },
            Err(e) => Err(e.into()),
        }
    }

    fn run(&self, script: &str, verbose: bool) -> Result<(), CliErrorKind> {
        let logger = DefaultLogger::default();
        let sessions = Sessions::default();
        let context = Context::new(
            &self.key,
            self.dispatcher,
            self.retriever,
            self.loader,
            &logger,
            &sessions,
        );
        let mut register = Register::default();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let code = self.load(script)?;
        for stmt in nasl_syntax::parse(&code) {
            match stmt {
                Ok(stmt) => {
                    if verbose {
                        eprintln!("> {stmt}");
                    }
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
                            if verbose {
                                eprintln!("=> {r:?}");
                            }
                        }
                    }
                }

                Err(e) => return Err(e.into()),
            };
        }
        Ok(())
    }
}

fn build_loader(feed: Option<PathBuf>) -> Box<dyn Loader> {
    match feed {
        Some(x) => Box::new(FSPluginLoader::new(x)),
        None => Box::<NoOpLoader>::default(),
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
fn build_dispatcher<K>(db: &Db) -> Box<dyn Storage<K>>
where
    K: AsRef<str> + Display + Default + From<String> + 'static,
{
    match db {
        Db::InMemory => Box::<DefaultDispatcher<K>>::default(),
        Db::Redis(url) => Box::new(redis_storage::NvtDispatcher::as_dispatcher(url).unwrap()),
    }
}

pub fn run(db: &Db, feed: Option<PathBuf>, script: String, verbose: bool) -> Result<(), CliError> {
    let k = String::default();
    let storage = build_dispatcher(db);
    let loader = build_loader(feed.clone());

    let runner = Run::new(
        k,
        feed,
        storage.as_dispatcher(),
        storage.as_retriever(),
        &*loader,
    );
    runner.run(&script, verbose).map_err(|e| CliError {
        filename: script,
        kind: e,
    })
}
