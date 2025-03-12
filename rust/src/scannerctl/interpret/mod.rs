// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    fs::{self},
    path::PathBuf,
};

use futures::StreamExt;
use scannerlib::{feed, scheduling::SchedulerStorage, storage::items::nvt::Oid};
use scannerlib::{nasl::utils::context::ContextStorage, storage::inmemory::InMemoryStorage};
use scannerlib::{
    nasl::{interpreter::ForkingInterpreter, utils::error::ReturnBehavior},
    storage::redis::{RedisCtx, RedisStorage, FEEDUPDATE_SELECTOR},
};
use scannerlib::{
    nasl::{
        interpreter::InterpretErrorKind,
        prelude::*,
        syntax::{load_non_utf8_path, LoadError},
        Loader, NoOpLoader,
    },
    storage::items::nvt::Nvt,
};

use crate::{CliError, CliErrorKind, Db};

struct Run<L, S> {
    context_builder: ContextFactory<L, S>,
    target: String,
    scan_id: String,
}

struct RunBuilder<L, S> {
    loader: L,
    storage: S,
    target: String,
    scan_id: String,
}

impl Default for RunBuilder<NoOpLoader, InMemoryStorage> {
    fn default() -> Self {
        Self {
            storage: InMemoryStorage::default(),
            loader: NoOpLoader::default(),
            target: String::default(),
            scan_id: "scannerctl".to_string(),
        }
    }
}

impl<L, S> RunBuilder<L, S>
where
    S: ContextStorage,
    L: Loader,
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
            context_builder: ContextFactory::new(self.loader, self.storage),
            scan_id: self.scan_id,
            target: self.target,
        }
    }
}

impl<L, S> Run<L, S>
where
    L: Loader,
    S: ContextStorage + SchedulerStorage,
{
    fn load(&self, script: &str) -> Result<String, CliErrorKind> {
        match load_non_utf8_path(&script) {
            Ok(x) => Ok(x),
            Err(LoadError::NotFound(_)) => {
                if let Some(vt) = self
                    .context_builder
                    .storage
                    .retrieve(&Oid(script.to_string()))?
                {
                    Ok(self.context_builder.loader.load(&vt.filename)?)
                } else {
                    Err(LoadError::NotFound(script.to_string()).into())
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn run(&self, script: &str) -> Result<(), CliErrorKind> {
        let context = self.context_builder.build(
            scannerlib::storage::ScanID(self.scan_id.clone()),
            &self.target,
            script.into(),
        );
        let register = RegisterBuilder::build();
        let code = self.load(script)?;
        let mut results = ForkingInterpreter::new(&code, register, &context).stream();
        while let Some(result) = results.next().await {
            let r = match result {
                Ok(x) => x,
                Err(e) => {
                    if let InterpretErrorKind::FunctionCallError(ref fe) = e.kind {
                        match fe.kind.return_behavior() {
                            ReturnBehavior::ExitScript => return Err(e.into()),
                            ReturnBehavior::ReturnValue(val) => {
                                tracing::warn!("{}", e.to_string());
                                val.clone()
                            }
                        }
                    } else {
                        return Err(e.into());
                    }
                }
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

fn create_redis_storage(url: &str) -> RedisStorage<RedisCtx> {
    RedisStorage::init(url, FEEDUPDATE_SELECTOR).unwrap()
}

async fn load_feed_by_exec<S>(storage: &S, pl: &FSPluginLoader) -> Result<(), CliError>
where
    S: ContextStorage,
{
    // update feed with storage

    tracing::info!("loading feed. This may take a while.");
    let verifier = feed::HashSumNameLoader::sha256(pl)?;
    let updater = feed::Update::init("scannerctl", 5, pl, storage, verifier);
    updater.perform_update().await?;
    tracing::info!("loaded feed.");
    Ok(())
}

fn load_feed_by_json(store: &InMemoryStorage, path: &PathBuf) -> Result<(), CliError> {
    tracing::info!(path=?path, "loading feed via json. This may take a while.");
    let buf = fs::read_to_string(path).map_err(|e| CliError::load_error(e, path))?;
    let vts: Vec<Nvt> = serde_json::from_str(&buf)?;
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
    target: Option<String>,
) -> Result<(), CliError> {
    let builder = RunBuilder::default()
        .target(target.unwrap_or_default())
        .scan_id(format!("scannerctl-{script}"));
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
            let storage = InMemoryStorage::new();
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
