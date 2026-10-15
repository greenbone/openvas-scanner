// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::BTreeSet,
    fs::{self},
    path::{Path, PathBuf},
};

use scannerlib::nasl::{
    NaslFile, NaslValue, ScriptCtx, WithErrorInfo,
    interpreter::InterpreterErrorKind,
    syntax::{LoadError, LoadErrorKind, Loader},
    utils::ctx::{NotusCtx, TargetId},
};
use scannerlib::{
    feed,
    nasl::{
        Register, ScanCtx,
        interpreter::ForkingInterpreter,
        nasl_std_executor,
        utils::{
            ctx::{Ports, Target},
            error::ReturnBehavior,
        },
    },
    scanner::preferences::preference::ScanPrefs,
    storage::{
        ScanID,
        items::{kb::KbContextKey, nvt::Oid},
    },
};
use scannerlib::{models::VTData, nasl::utils::ctx::CtxTargets};
use scannerlib::{nasl::utils::ctx::ContextStorage, storage::inmemory::InMemoryStorage};

use crate::{CliError, CliErrorKind, Db, Filename};

async fn load_from_feed<'a>(
    loader: &'a Loader,
    storage: &impl ContextStorage,
    script: &Path,
) -> Result<NaslFile<'a>, CliErrorKind> {
    let path = std::path::absolute(script).map_err(|error| LoadError::from_io(script, error))?;
    match loader.load_nasl(path) {
        Ok(file) => Ok(file),
        Err(e) if matches!(e.kind(), LoadErrorKind::NotFound) => {
            match storage
                .retrieve(&Oid(script.to_string_lossy().to_string()))
                .await?
            {
                Some(vt) => Ok(loader.load_nasl(&vt.filename)?),
                _ => Err(LoadError::not_found(script).into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

async fn run_with_context(
    ctx: ScanCtx<'_>,
    file: NaslFile<'_>,
    target_id: TargetId,
) -> Result<(), CliErrorKind> {
    let register = Register::default();
    let ast = file
        .parse()
        .emit_errors()
        .map_err(CliErrorKind::SyntaxError)?;
    let script_ctx = ScriptCtx::new(&ctx, target_id, VTData::from_filename(file.source().name()));
    let mut interpreter = ForkingInterpreter::new(ast, register, &ctx, script_ctx);
    while let Some(result) = interpreter.next().await {
        let r = match result {
            Ok(x) => x,
            Err(e) => {
                if let InterpreterErrorKind::FunctionCallError(ref fe) = e.kind {
                    match fe.kind.return_behavior() {
                        ReturnBehavior::ExitScript => {
                            file.emit_errors(std::iter::once(&e));
                            return Err(e.into());
                        }
                        ReturnBehavior::ReturnValue(val) => {
                            file.emit_errors(std::iter::once(&e));
                            val.clone()
                        }
                    }
                } else {
                    file.emit_errors(std::iter::once(&e));
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

async fn load_feed_by_exec<S>(storage: &S, pl: &Loader) -> Result<(), CliError>
where
    S: ContextStorage,
{
    // update feed with storage

    tracing::info!("loading feed. This may take a while.");
    let verifier = feed::HashSumNameLoader::sha256(pl)?;
    let updater = feed::Update::init("scannerctl", 5, pl.clone(), storage, verifier);
    updater.perform_update().await?;
    tracing::info!("loaded feed.");
    Ok(())
}

fn load_feed_by_json(store: &InMemoryStorage, path: &PathBuf) -> Result<(), CliError> {
    tracing::info!(path=?path, "loading feed via json. This may take a while.");
    let buf = fs::read_to_string(path).map_err(|e| {
        CliErrorKind::LoadError(LoadError::from_io(path.to_owned(), e)).with(Filename(path))
    })?;
    let vts: Vec<VTData> = serde_json::from_str(&buf)?;
    let all_vts = vts.into_iter().map(|v| (v.filename.clone(), v)).collect();

    store
        .set_vts(all_vts)
        .map_err(|e| CliErrorKind::StorageError(e).with(Filename(path)))?;
    tracing::info!("loaded feed.");
    Ok(())
}

// TODO: Redesign
#[allow(clippy::too_many_arguments)]
async fn run_on_storage<S: ContextStorage>(
    storage: S,
    loader: &Loader,
    target: Target,
    kb: Vec<String>,
    ports: Ports,
    file: NaslFile<'_>,
    scan_preferences: ScanPrefs,
    notus: Option<NotusCtx>,
) -> Result<(), CliErrorKind> {
    let scan_id = ScanID(format!("scannerctl-{}", file.source().name()));
    let kbctx = (
        scan_id.clone(),
        scannerlib::storage::Target(target.ip_addr().to_string()),
    );
    for s in kb.iter() {
        match s.split_once("=") {
            Some((k, v)) => {
                let storage_ctx = KbContextKey(kbctx.clone(), k.into());
                let _ = storage
                    .dispatch(storage_ctx, v.into())
                    .await
                    .map_err(CliErrorKind::StorageError);
            }
            None => return Err(CliErrorKind::InvalidCmdOpt(s.to_string())),
        }
    }

    let executor = nasl_std_executor();
    let (targets, target_id) = CtxTargets::single(target, ports);
    let ctx = ScanCtx::new(
        scan_id,
        targets,
        &storage,
        loader,
        &executor,
        scan_preferences,
        Vec::new(),
        notus,
    );
    run_with_context(ctx, file, target_id).await
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    db: &Db,
    feed: Option<PathBuf>,
    script: &Path,
    target: Option<String>,
    kb: Vec<String>,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    scan_preferences: ScanPrefs,
    notus: Option<NotusCtx>,
) -> Result<(), CliError> {
    let target = target
        .map(|target| {
            Target::resolve_hostname(&target)
                .unwrap_or_else(|| panic!("Hostname resolution failed for target {target}"))
        })
        .unwrap_or(Target::localhost());
    let ports = Ports {
        tcp: BTreeSet::from_iter(tcp_ports),
        udp: BTreeSet::from_iter(udp_ports),
    };

    let result = match (db, feed) {
        (Db::InMemory, None) => {
            let filename = script
                .file_name()
                .ok_or_else(|| LoadError::not_a_file(script))?;
            let loader = Loader::from_feed_path(script.parent().unwrap());
            let file = loader
                .load_nasl(filename)
                .map_err(|error| CliErrorKind::from(error).with(Filename(script)))?;
            run_on_storage(
                InMemoryStorage::default(),
                &loader,
                target,
                kb,
                ports,
                file,
                scan_preferences,
                notus,
            )
            .await
        }
        (Db::InMemory, Some(path)) => {
            let storage = InMemoryStorage::new();
            let guessed_feed_json = path.join("feed.json");
            let loader = Loader::from_feed_path(path.clone());
            if guessed_feed_json.exists() {
                load_feed_by_json(&storage, &guessed_feed_json)?
            } else {
                load_feed_by_exec(&storage, &loader).await?
            }
            let file = load_from_feed(&loader, &storage, script)
                .await
                .map_err(|error| error.with(Filename(script)))?;
            run_on_storage(
                storage,
                &loader,
                target,
                kb,
                ports,
                file,
                scan_preferences,
                notus,
            )
            .await
        }
    };

    result.map_err(|e| CliError {
        filename: Some(script.to_owned()),
        kind: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn standalone_script_uses_its_parent_for_includes() {
        let cwd = std::env::current_dir().unwrap();
        let dir = tempfile::tempdir_in(&cwd).unwrap();
        std::fs::write(
            dir.path().join("main.nasl"),
            r#"include("value.inc"); if (value != 42) { unknown_function(); }"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("value.inc"), "value = 42;").unwrap();
        let script = dir.path().join("main.nasl");

        run(
            &Db::InMemory,
            None,
            script.strip_prefix(&cwd).unwrap(),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ScanPrefs::new(),
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn feed_loading_accepts_filesystem_paths_and_oids() {
        let direct = std::path::absolute("local.nasl").unwrap();
        let loader = Loader::test()
            .with_file(direct.to_str().unwrap(), String::new())
            .with_file("plugins/main.nasl", String::new())
            .build();
        let storage = InMemoryStorage::new();
        let mut vt = VTData::from_filename("plugins/main.nasl");
        vt.oid = "1.2.3.4".into();
        storage
            .set_vts(std::collections::HashMap::from([(vt.filename.clone(), vt)]))
            .unwrap();

        for (script, expected) in [
            (Path::new("local.nasl"), direct.as_path()),
            (Path::new("1.2.3.4"), Path::new("plugins/main.nasl")),
        ] {
            let file = load_from_feed(&loader, &storage, script).await.unwrap();
            assert_eq!(file.source().path(), expected);
        }
    }
}
