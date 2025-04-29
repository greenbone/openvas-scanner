// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    fs::{self},
    path::{Path, PathBuf},
};

use futures::StreamExt;
use scannerlib::{
    feed,
    nasl::{
        Context,
        interpreter::ForkingInterpreter,
        nasl_std_functions,
        utils::{context::Target, error::ReturnBehavior},
    },
    storage::{ScanID, items::nvt::Oid},
};
use scannerlib::{nasl::utils::context::ContextStorage, storage::inmemory::InMemoryStorage};
use scannerlib::{
    nasl::{
        ContextBuilder, FSPluginLoader, Loader, NaslValue, NoOpLoader, RegisterBuilder,
        WithErrorInfo,
        interpreter::InterpretErrorKind,
        syntax::{LoadError, load_non_utf8_path},
    },
    storage::items::nvt::Nvt,
};

use crate::{CliError, CliErrorKind, Db, Filename};

fn load(ctx: &Context, script: &Path) -> Result<String, CliErrorKind> {
    match load_non_utf8_path(&script) {
        Ok(x) => Ok(x),
        Err(LoadError::NotFound(_)) => {
            match ctx
                .storage()
                .retrieve(&Oid(script.to_string_lossy().to_string()))?
            {
                Some(vt) => Ok(ctx.loader().load(&vt.filename)?),
                _ => Err(LoadError::NotFound(script.to_string_lossy().to_string()).into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

async fn run_with_context(context: Context<'_>, script: &Path) -> Result<(), CliErrorKind> {
    let register = RegisterBuilder::build();
    let code = load(&context, script)?;
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
    let buf = fs::read_to_string(path).map_err(|e| {
        CliErrorKind::LoadError(LoadError::Dirty(format!("{e}"))).with(Filename(path))
    })?;
    let vts: Vec<Nvt> = serde_json::from_str(&buf)?;
    let all_vts = vts.into_iter().map(|v| (v.filename.clone(), v)).collect();

    store
        .set_vts(all_vts)
        .map_err(|e| CliErrorKind::StorageError(e).with(Filename(path)))?;
    tracing::info!("loaded feed.");
    Ok(())
}

async fn run_on_storage<S: ContextStorage, L: Loader>(
    storage: S,
    loader: L,
    target: Target,
    script: &Path,
) -> Result<(), CliErrorKind> {
    let scan_id = ScanID(format!("scannerctl-{}", script.to_string_lossy()));
    let filename = script;
    let cb = ContextBuilder {
        storage: &storage,
        loader: &loader,
        executor: &nasl_std_functions(),
        target,
        scan_id,
        filename,
        scan_preferences: Vec::new(),
    };
    run_with_context(cb.build(), script).await
}

pub async fn run(
    db: &Db,
    feed: Option<PathBuf>,
    script: &Path,
    target: Option<String>,
) -> Result<(), CliError> {
    let target = target
        .map(|target| {
            Target::resolve_hostname(&target)
                .unwrap_or_else(|| panic!("Hostname resolution failed for target {target}"))
        })
        .unwrap_or(Target::localhost());
    let result = match (db, feed) {
        (Db::InMemory, None) => {
            run_on_storage(
                InMemoryStorage::default(),
                NoOpLoader::default(),
                target,
                script,
            )
            .await
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
            run_on_storage(storage, loader, target, script).await
        }
    };

    result.map_err(|e| CliError {
        filename: Some(script.to_owned()),
        kind: e,
    })
}
