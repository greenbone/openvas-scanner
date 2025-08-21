// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod update;
use std::{io, path::PathBuf};

// re-export to work around name conflict

use clap::Subcommand;
use scannerlib::{
    nasl::syntax::LoadError,
    storage::{
        error::StorageError,
        infisto::json::{ArrayWrapper, JsonStorage},
        redis::{
            FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR, NameSpaceSelector, RedisCtx, RedisStorage,
        },
    },
};
use tracing::warn;

// use scannerlib::feed::{FeedReplacer, ReplaceCommand};

use crate::{CliError, CliErrorKind, get_path_from_openvas, notus_update, read_openvas_config};

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
}

/// Runs nasl scripts in description mode and updates data into Redis
#[derive(clap::Parser)]
struct UpdateArgs {
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
struct TransformArgs {
    /// Path to the feed.
    #[clap(short, long)]
    path: PathBuf,
}

fn make_redis_storage(
    redis: &str,
    selector: &[NameSpaceSelector],
) -> Result<RedisStorage<RedisCtx>, CliErrorKind> {
    Ok(RedisStorage::init(redis, selector).map_err(StorageError::from)?)
}

async fn update_vts(
    redis: &str,
    vts_path: Option<PathBuf>,
    signature_check: bool,
) -> Result<(), CliError> {
    let path = vts_path.clone().unwrap_or_else(|| {
        warn!("--vts-path not specified, trying to obtain VT path from openvas config");
        get_vts_path_from_openvas_config()
    });
    let redis_storage = make_redis_storage(redis, FEEDUPDATE_SELECTOR)?;
    update::run(redis_storage, &path, signature_check).await
}

async fn update_notus(
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
    let redis_storage = make_redis_storage(redis, NOTUSUPDATE_SELECTOR)?;
    notus_update::update::run(redis_storage, path, signature_check)
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

async fn update(args: UpdateArgs) -> Result<(), CliError> {
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
            let r2 = update_notus(&redis, args.notus_path, args.signature_check).await;
            r1.and(r2)
        }
    }
}

async fn transform(args: TransformArgs) -> Result<(), CliError> {
    let mut o = ArrayWrapper::new(io::stdout());
    let dispatcher = JsonStorage::new(&mut o);
    update::run_no_verifier(dispatcher, &args.path).await?;
    o.end()
        .map_err(StorageError::from)
        .map_err(|e| CliErrorKind::from(e).into())
}

pub async fn run(args: FeedArgs) -> Result<(), CliError> {
    match args.action {
        Action::Update(args) => update(args).await?,
        Action::Transform(args) => transform(args).await?,
    }
    Ok(())
}
