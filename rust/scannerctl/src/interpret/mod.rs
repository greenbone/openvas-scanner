// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::PathBuf;

use nasl_interpreter::{
    load_non_utf8_path, CodeInterpreter, FSPluginLoader, LoadError, NaslValue, NoOpLoader,
    RegisterBuilder,
};
use redis_storage::FEEDUPDATE_SELECTOR;
use storage::{ContextKey, DefaultDispatcher};

use crate::{CliError, CliErrorKind, Db};

struct Run<L, S> {
    context_builder: nasl_interpreter::ContextFactory<L, S>,
    target: String,
    scan_id: String,
}

struct RunBuilder<L, S> {
    loader: L,
    storage: S,
    target: String,
    scan_id: String,
}

impl Default for RunBuilder<NoOpLoader, DefaultDispatcher> {
    fn default() -> Self {
        Self {
            storage: DefaultDispatcher::default(),
            loader: NoOpLoader::default(),
            target: String::default(),
            scan_id: "scannerctl".to_string(),
        }
    }
}

impl<L, S> RunBuilder<L, S>
where
    S: storage::Storage,
    L: nasl_interpreter::Loader,
{
    pub fn storage<S2>(self, s: S2) -> RunBuilder<L, S2> {
        RunBuilder {
            loader: self.loader,
            storage: s,
            target: self.target,
            scan_id: self.scan_id,
        }
    }

    pub fn loader<L2>(self, l: L2) -> RunBuilder<L2, S> {
        RunBuilder {
            loader: l,
            storage: self.storage,
            target: self.target,
            scan_id: self.scan_id,
        }
    }

    pub fn target(mut self, target: String) -> RunBuilder<L, S> {
        self.target = target;
        self
    }

    pub fn scan_id(mut self, scan_id: String) -> RunBuilder<L, S> {
        self.scan_id = scan_id;
        self
    }

    pub fn build(self) -> Run<L, S> {
        Run {
            context_builder: nasl_interpreter::ContextFactory::new(self.loader, self.storage),
            scan_id: self.scan_id,
            target: self.target,
        }
    }
}

impl<L, S> Run<L, S>
where
    L: nasl_interpreter::Loader,
    S: storage::Storage,
{
    fn load(&self, script: &str) -> Result<String, CliErrorKind> {
        match load_non_utf8_path(&script) {
            Ok(x) => Ok(x),
            Err(LoadError::NotFound(_)) => {
                let iter = self.context_builder.storage.retrieve_by_field(
                    storage::Field::NVT(storage::item::NVTField::Oid(script.into())),
                    // TODO: maybe NvtField::FileName would be better?
                    storage::Retrieve::NVT(None),
                )?;
                let results: Option<String> = iter
                    .filter_map(|(k, _)| match k {
                        ContextKey::Scan(_) => None,
                        ContextKey::FileName(f) => Some(f.to_string()),
                    })
                    .next();
                match results {
                    Some(f) => Ok(self.context_builder.loader.load(&f)?),
                    None => Err(LoadError::NotFound(script.to_string()).into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    fn run(&self, script: &str) -> Result<(), CliErrorKind> {
        let context = self
            .context_builder
            .build(ContextKey::Scan(self.scan_id.clone()), self.target.clone());
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

fn create_redis_storage(
    url: &str,
) -> storage::item::PerItemDispatcher<redis_storage::CacheDispatcher<redis_storage::RedisCtx>> {
    redis_storage::CacheDispatcher::as_dispatcher(url, FEEDUPDATE_SELECTOR).unwrap()
}

fn create_fp_loader<S>(storage: &S, path: PathBuf) -> Result<FSPluginLoader<PathBuf>, CliError>
where
    S: storage::Dispatcher,
{
    // update feed with storage

    tracing::info!("loading feed. This may take a while.");
    let result = FSPluginLoader::new(path);
    let verifier = feed::HashSumNameLoader::sha256(&result)?;
    let updater = feed::Update::init("scannerctl", 5, &result, storage, verifier);
    for u in updater {
        tracing::warn!(updated=?u);
        u?;
    }
    tracing::info!("loaded feed.");
    Ok(result)
}

pub fn run(
    db: &Db,
    feed: Option<PathBuf>,
    script: &str,
    target: Option<String>,
) -> Result<(), CliError> {
    let builder = RunBuilder::default()
        .target(target.unwrap_or_default())
        .scan_id(format!("scannerctl-{script}"));
    let result = match (db, feed) {
        (Db::Redis(url), None) => builder
            .storage(create_redis_storage(url))
            .build()
            .run(script),
        (Db::InMemory, None) => builder.build().run(script),
        (Db::Redis(url), Some(path)) => {
            let storage = create_redis_storage(url);
            let builder = RunBuilder::default().loader(create_fp_loader(&storage, path)?);
            builder.storage(storage).build().run(script)
        }
        (Db::InMemory, Some(path)) => {
            let storage = DefaultDispatcher::new(true);
            let builder = RunBuilder::default().loader(create_fp_loader(&storage, path)?);
            builder.storage(storage).build().run(script)
        }
    };

    result.map_err(|e| CliError {
        filename: script.to_string(),
        kind: e,
    })
}
