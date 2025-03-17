// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod update;
use std::{io, path::PathBuf};

use clap::{ArgAction, Command, arg, value_parser};
// re-export to work around name conflict

use scannerlib::{
    nasl::syntax::LoadError,
    storage::{
        error::StorageError,
        infisto::json::{ArrayWrapper, JsonStorage},
        redis::{FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR, RedisStorage},
    },
};

// use scannerlib::feed::{FeedReplacer, ReplaceCommand};

use crate::{CliError, CliErrorKind, get_path_from_openvas, notusupdate, read_openvas_config};

pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand(
    crate::add_verbose(
            Command::new("feed")
                .about("Handles feed related tasks")
                .subcommand_required(true)
                .subcommand(Command::new("update")
                .about("Runs nasl scripts in description mode and updates data into redis")
                .arg(arg!(-v --"vts-only" "Load only nvts into redis cache").required(false).action(ArgAction::SetTrue))
                .arg(arg!(-n --"notus-only" "Load only Notus advisories into redis cache").required(false).action(ArgAction::SetTrue))
                .arg(arg!(--"vts-path" <FILE> "Path to the feed.").required(false)
                     .value_parser(value_parser!(PathBuf)))
                .arg(arg!(--"notus-path" <FILE> "Path to the notus advisories.").required(false)
                     .value_parser(value_parser!(PathBuf)))
                .arg(arg!(-x --"signature-check" "Enable NASL signature check.").required(false).action(ArgAction::SetTrue))
                .arg(arg!(-r --redis <VALUE> "Redis url. Must either start `unix://` or `redis://`.").required(false))
                )
                .subcommand(Command::new("transform")
                .about("Runs nasl scripts in description mode and returns it as a json array into stdout")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                )
                .subcommand(Command::new("transpile")
                .about("Transforms each nasl script and inc file based on the given rules.")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                .arg(arg!(-r --rules <FILE> "Path to transpiler rules.").required(true)
                    .value_parser(value_parser!(PathBuf)))
                )
        ))
}

pub async fn update_vts(
    redis: &str,
    signature_check: bool,
    args: &clap::ArgMatches,
) -> Result<(), CliError> {
    let path = get_vts_path("vts-path", args);
    let redis_storage = RedisStorage::init(redis, FEEDUPDATE_SELECTOR)
        .map_err(StorageError::from)
        .map_err(|e| CliError {
            filename: format!("{path:?}"),
            kind: e.into(),
        })?;
    update::run(redis_storage, path, signature_check).await
}

pub async fn update_notus(
    redis: &str,
    signature_check: bool,
    args: &clap::ArgMatches,
) -> Result<(), CliError> {
    let path = match args.get_one::<PathBuf>("notus-path") {
        Some(p) => p.to_path_buf(),
        None => {
            return Err(CliError {
                filename: "".to_string(),
                kind: CliErrorKind::LoadError(LoadError::Dirty(
                    "Path to the notus advisories is mandatory".to_string(),
                )),
            });
        }
    };

    let dispatcher = RedisStorage::init(redis, NOTUSUPDATE_SELECTOR)
        .map_err(StorageError::from)
        .map_err(|e| CliError {
            filename: format!("{path:?}"),
            kind: e.into(),
        })?;
    notusupdate::update::run(dispatcher, path, signature_check)
}

pub async fn update(args: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let redis = match args.get_one::<String>("redis").cloned() {
        Some(x) => x,
        None => {
            let config =
                read_openvas_config().expect("openvas -s must be executable when path is not set");
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
    };
    let signature_check = args
        .get_one::<bool>("signature-check")
        .cloned()
        .unwrap_or(false);

    let loadup_notus_only = args.get_one::<bool>("notus-only").cloned().unwrap_or(false);

    let loadup_vts_only = args.get_one::<bool>("vts-only").cloned().unwrap_or(false);

    match (loadup_notus_only, loadup_vts_only) {
        (true, true) => Some(Err(CliError {
            filename: "".to_string(),
            kind: CliErrorKind::LoadError(LoadError::Dirty(
                "Please do not use --notus-only and --vts-only together".to_string(),
            )),
        })),
        (false, true) => Some(update_vts(&redis, signature_check, args).await),
        (true, false) => Some(update_notus(&redis, signature_check, args).await),
        (false, false) => {
            let r1 = update_vts(&redis, signature_check, args).await;
            let r2 = update_vts(&redis, signature_check, args).await;
            Some(r1.and(r2))
        }
    }
}

fn get_vts_path(key: &str, args: &clap::ArgMatches) -> PathBuf {
    args.get_one::<PathBuf>(key).cloned().unwrap_or_else(|| {
        let config =
            read_openvas_config().expect("openvas -s must be executable when path is not set");
        get_path_from_openvas(config)
    })
}

pub async fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "feed")?;
    match args.subcommand() {
        Some(("update", args)) => update(args).await,
        Some(("transform", args)) => {
            let path = get_vts_path("path", args);

            let mut o = ArrayWrapper::new(io::stdout());
            let dispatcher = JsonStorage::new(&mut o);
            Some(match update::run(dispatcher, path, false).await {
                Ok(_) => o.end().map_err(StorageError::from).map_err(|se| CliError {
                    filename: "".to_string(),
                    kind: se.into(),
                }),
                Err(e) => Err(e),
            })
        }

        Some(("transpile", _)) => {
            panic!()
        }
        _ => unreachable!("subcommand_required prevents None"),
    }
}
