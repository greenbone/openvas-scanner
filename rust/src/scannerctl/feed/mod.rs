// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod filter;
mod transpile;
pub mod update;
use std::{
    io,
    path::{Path, PathBuf},
};

// re-export to work around name conflict

use clap::Subcommand;
use filter::FilterArgs;
use scannerlib::{
    nasl::{syntax::LoadError, WithErrorInfo},
    storage::{
        json::{ArrayWrapper, ItemDispatcher},
        redis::{
            CacheDispatcher, NameSpaceSelector, RedisCtx, FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR,
        },
    },
};

use scannerlib::storage::{item::PerItemDispatcher, StorageError};
use tracing::warn;
use transpile::TranspileArgs;

use crate::{
    get_path_from_openvas, notus_update, read_openvas_config, CliError, CliErrorKind, Filename,
};

/// Handle feed related tasks
#[derive(clap::Parser)]
pub struct FeedArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    Update(UpdateArgs),
    Transform(TransformArgs),
    Transpile(TranspileArgs),
    Filter(FilterArgs),
}

/// Runs nasl scripts in description mode and updates data into Redis
#[derive(clap::Parser)]
pub struct UpdateArgs {
    /// Path to the feed.
    #[clap(long)]
    vts_path: Option<PathBuf>,
    /// Path to the notus advisories.
    #[clap(long)]
    notus_path: Option<PathBuf>,
    /// Only load vts into Redis cache.
    #[clap(long)]
    vts_only: bool,
    /// Only load Notus advisories into Redis cache.
    #[clap(long)]
    notus_only: bool,
    /// Perform a NASL signature check
    #[clap(short, long)]
    signature_check: bool,
    // TODO: This was the previous docstring, but this fact is not at all reflected in the code.
    /// Redis url. Must either start `unix://` or `redis://`.
    #[clap(short, long)]
    redis: Option<String>,
}

#[derive(clap::Parser)]
pub struct TransformArgs {
    /// Path to the feed.
    #[clap(short, long)]
    path: PathBuf,
}

fn get_dispatcher(
    redis: &str,
    path: &Path,
    selector: &[NameSpaceSelector],
) -> Result<PerItemDispatcher<CacheDispatcher<RedisCtx>>, CliError> {
    CacheDispatcher::as_dispatcher(redis, selector)
        .map_err(StorageError::from)
        .map_err(|e| CliErrorKind::from(e).with(Filename(Path::new(&format!("{path:?}")))))
}

pub async fn update_vts(
    redis: &str,
    vts_path: Option<PathBuf>,
    signature_check: bool,
) -> Result<(), CliError> {
    let path = vts_path.clone().unwrap_or_else(|| {
        warn!("--vts-path not specified, trying to obtain VT path from openvas config");
        get_vts_path_from_openvas_config()
    });
    let dispatcher = get_dispatcher(redis, &path, FEEDUPDATE_SELECTOR)?;
    update::run(dispatcher, &path, signature_check).await
}

pub async fn update_notus(
    redis: &str,
    notus_path: Option<PathBuf>,
    signature_check: bool,
) -> Result<(), CliError> {
    let path = match notus_path {
        Some(p) => p,
        None => {
            return Err(CliErrorKind::LoadError(LoadError::Dirty(
                "Path to the notus advisories is mandatory".to_string(),
            ))
            .into());
        }
    };

    let dispatcher = get_dispatcher(redis, &path, NOTUSUPDATE_SELECTOR)?;
    notus_update::update::run(dispatcher, path, signature_check)
}

fn get_vts_path_from_openvas_config() -> PathBuf {
    let config = read_openvas_config().expect("openvas -s must be executable when path is not set");
    get_path_from_openvas(config)
}

fn get_redis_url_from_openvas_config() -> String {
    let config = read_openvas_config().expect("openvas -s must be executable when path is not set");
    let dba = config
        .get("default", "db_address")
        .expect("openvas -s must contain db_address");

    if dba.starts_with("redis://") || dba.starts_with("unix://") {
        dba
    } else if dba.starts_with("tcp://") {
        dba.replace("tcp://", "redis://")
    } else {
        format!("unix://{dba}")
    }
}

pub async fn update(args: UpdateArgs) -> Result<(), CliError> {
    let redis = args.redis.unwrap_or_else(|| {
        warn!("--redis not specified, trying to obtain Redis url from openvas config");
        get_redis_url_from_openvas_config()
    });

    match (args.notus_only, args.vts_only) {
        (true, true) => Err(CliErrorKind::LoadError(LoadError::Dirty(
            "--notus-only and --vts-only not allowed at the same time".to_string(),
        ))
        .into()),
        (false, true) => update_vts(&redis, args.vts_path, args.signature_check).await,
        (true, false) => update_notus(&redis, args.notus_path, args.signature_check).await,
        (false, false) => {
            let r1 = update_vts(&redis, args.vts_path, args.signature_check).await;
            // TODO: Confirm that I'm not insane and this was completely wrong before.
            let r2 = update_notus(&redis, args.notus_path, args.signature_check).await;
            r1.and(r2)
        }
    }
}

async fn transform(args: TransformArgs) -> Result<(), CliError> {
    let mut o = ArrayWrapper::new(io::stdout());
    let dispatcher = ItemDispatcher::as_dispatcher(&mut o);
    update::run(dispatcher, &args.path, false).await?;
    o.end()
        .map_err(StorageError::from)
        .map_err(|e| CliErrorKind::from(e).into())
}

pub async fn run(args: FeedArgs) -> Result<(), CliError> {
    match args.action {
        Action::Update(args) => update(args).await?,
        Action::Transform(args) => transform(args).await?,
        Action::Transpile(args) => transpile::run(args).await?,
        Action::Filter(args) => filter::run(args)?,
    }
    Ok(())
}
