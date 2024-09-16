// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    fs::{self},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use futures::StreamExt;
use nasl_interpreter::{
    load_non_utf8_path, CodeInterpreter, FSPluginLoader, LoadError, NaslValue, NoOpLoader,
    RegisterBuilder,
};
use redis_storage::FEEDUPDATE_SELECTOR;
use storage::{ContextKey, DefaultDispatcher};

use crate::{CliError, CliErrorKind, Db};

struct Run<L, S> {
    context_builder: nasl_interpreter::ContextFactory<L, S>,
    scan_id: String,
}

struct RunBuilder<L, S> {
    loader: L,
    storage: S,
    target: IpAddr,
    scan_id: String,
}

impl Default for RunBuilder<NoOpLoader, DefaultDispatcher> {
    fn default() -> Self {
        Self {
            storage: DefaultDispatcher::default(),
            loader: NoOpLoader::default(),
            target: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
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

    pub fn target(mut self, target: IpAddr) -> RunBuilder<L, S> {
        self.target = target;
        self
    }

    pub fn scan_id(mut self, scan_id: String) -> RunBuilder<L, S> {
        self.scan_id = scan_id;
        self
    }

    pub fn build(self) -> Run<L, S> {
        Run {
            context_builder: nasl_interpreter::ContextFactory::new(
                self.target,
                self.loader,
                self.storage,
            ),
            scan_id: self.scan_id,
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
                        ContextKey::Scan(..) => None,
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

    async fn run(&self, script: &str) -> Result<(), CliErrorKind> {
        let context = self.context_builder.build(ContextKey::Scan(
            self.scan_id.clone(),
            self.context_builder.target.clone(),
        ));
        let register = RegisterBuilder::build();
        let code = self.load(script)?;
        let results: Vec<_> = CodeInterpreter::new(&code, register, &context)
            .stream()
            .collect()
            .await;
        for result in results {
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

        Ok(())
    }
}

fn create_redis_storage(
    url: &str,
) -> storage::item::PerItemDispatcher<redis_storage::CacheDispatcher<redis_storage::RedisCtx>> {
    redis_storage::CacheDispatcher::as_dispatcher(url, FEEDUPDATE_SELECTOR).unwrap()
}

async fn load_feed_by_exec<S>(storage: &S, pl: &FSPluginLoader) -> Result<(), CliError>
where
    S: storage::Dispatcher,
{
    // update feed with storage

    tracing::info!("loading feed. This may take a while.");
    let verifier = feed::HashSumNameLoader::sha256(pl)?;
    let updater = feed::Update::init("scannerctl", 5, pl, storage, verifier);
    updater.perform_update().await?;
    tracing::info!("loaded feed.");
    Ok(())
}

fn load_feed_by_json(store: &DefaultDispatcher, path: &PathBuf) -> Result<(), CliError> {
    tracing::info!(path=?path, "loading feed via json. This may take a while.");
    let buf = fs::read_to_string(path).map_err(|e| CliError::load_error(e, path))?;
    let vts: Vec<storage::item::Nvt> = serde_json::from_str(&buf)?;
    let all_vts = vts.into_iter().map(|v| (v.filename.clone(), v)).collect();

    store.set_vts(all_vts).map_err(|e| CliError {
        filename: path.to_owned().to_string_lossy().to_string(),
        kind: e.into(),
    })?;
    tracing::info!("loaded feed.");
    Ok(())
}

pub async fn run(
    db: &Db,
    feed: Option<PathBuf>,
    script: &str,
    target: Option<IpAddr>,
) -> Result<(), CliError> {
    let builder = RunBuilder::default().scan_id(format!("scannerctl-{script}"));
    let builder = if let Some(target) = target {
        builder.target(target)
    } else {
        builder
    };
    let result = match (db, feed) {
        (Db::Redis(url), None) => {
            builder
                .storage(create_redis_storage(url))
                .build()
                .run(script)
                .await
        }
        (Db::InMemory, None) => builder.build().run(script).await,
        (Db::Redis(url), Some(path)) => {
            let storage = create_redis_storage(url);
            let loader = FSPluginLoader::new(path);
            load_feed_by_exec(&storage, &loader).await?;
            let builder = RunBuilder::default().loader(loader);
            builder.storage(storage).build().run(script).await
        }
        (Db::InMemory, Some(path)) => {
            let storage = DefaultDispatcher::new();
            let guessed_feed_json = path.join("feed.json");
            let loader = FSPluginLoader::new(path.clone());
            if guessed_feed_json.exists() {
                load_feed_by_json(&storage, &guessed_feed_json)?
            } else {
                load_feed_by_exec(&storage, &loader).await?
            }

            let builder = RunBuilder::default().loader(loader);
            builder.storage(storage).build().run(script).await
        }
    };

    result.map_err(|e| CliError {
        filename: script.to_string(),
        kind: e,
    })
}
