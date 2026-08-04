// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod update;
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

// re-export to work around name conflict

use clap::Subcommand;
use scannerlib::{
    models::VTData,
    nasl::syntax::LoadError,
    storage::{
        Retriever,
        error::StorageError,
        inmemory::InMemoryStorage,
        items::nvt::Feed,
        redis::{FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR, NameSpaceSelector, RedisStorage},
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
) -> Result<RedisStorage, CliErrorKind> {
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
    if signature_check {
        update::run(redis_storage, &path, signature_check).await
    } else {
        update::run_no_verifier(redis_storage, &path).await
    }
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
    notus_update::update::run(redis_storage, path, signature_check).await
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

async fn transform_feed(path: &Path) -> Result<Vec<VTData>, CliError> {
    // An explanation for those who think the code below looks strange:
    //
    // The feed transform is supposed to iterate over all the nasl files in the feed, extract their
    // metadata from the description block and convert the results into a large json file. You might
    // think a reasonable implementation of this would simply loop over all the nasl files and call
    // some `parse_meta_data` function on the file and return the results. However, the reality is a
    // little more complicated - a small percentage of the scripts in the feed have actual control
    // flow in the description blocks. As a result, we need a full blown interpreter to run the NASL
    // script. The interpreter will then execute all the statements in the description block. The
    // builtin description functions which are called in those description blocks will write their
    // results into the local `vt` field of the scan context of the interpreter. When the scan
    // context is dropped, the fields are written into the storage from where we can then extract
    // them and convert them into json. This is very awkward but the alternative is to have a second
    // path for the interpreter, and that comes with a lot more code than doing something slightly
    // convoluted below.
    let storage = Arc::new(InMemoryStorage::default());
    update::run_no_verifier(Arc::clone(&storage), path).await?;
    Ok(storage
        .retrieve(&Feed)
        .await
        .map_err(CliErrorKind::from)?
        .unwrap_or_default())
}

async fn transform(args: TransformArgs) -> Result<(), CliError> {
    let vts = transform_feed(&args.path).await?;
    serde_json::to_writer(io::stdout().lock(), &vts)?;
    Ok(())
}

pub async fn run(args: FeedArgs) -> Result<(), CliError> {
    match args.action {
        Action::Update(args) => update(args).await?,
        Action::Transform(args) => transform(args).await?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs::File, path::Path};

    use scannerlib::models::VTData;

    #[tokio::test]
    async fn feed_transform() {
        let example_feed_path =
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/nasl"));
        let mut vts = super::transform_feed(example_feed_path).await.unwrap();
        let mut stored_vts: Vec<VTData> = serde_json::from_reader(
            File::open(example_feed_path.join("vt-metadata.json")).unwrap(),
        )
        .unwrap();
        vts.sort_by_key(|vt| (vt.oid.clone(), vt.name.clone()));
        stored_vts.sort_by_key(|vt| (vt.oid.clone(), vt.name.clone()));
        assert_eq!(vts, stored_vts);
    }
}
