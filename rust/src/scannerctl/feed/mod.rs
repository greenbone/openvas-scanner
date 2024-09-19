// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod update;
use std::{
    io,
    path::{Path, PathBuf},
};

use clap::{arg, value_parser, ArgAction, Command};
// re-export to work around name conflict

use scannerlib::{
    nasl::syntax::LoadError,
    storage::{
        json::{ArrayWrapper, ItemDispatcher},
        redis::{
            CacheDispatcher, NameSpaceSelector, RedisCtx, FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR,
        },
    },
};

use scannerlib::feed::{FeedReplacer, ReplaceCommand};
use scannerlib::storage::{item::PerItemDispatcher, StorageError};

use crate::{get_path_from_openvas, notusupdate, read_openvas_config, CliError, CliErrorKind};

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

fn get_dispatcher(
    redis: &str,
    path: &Path,
    selector: &[NameSpaceSelector],
) -> Result<PerItemDispatcher<CacheDispatcher<RedisCtx>>, CliError> {
    CacheDispatcher::as_dispatcher(redis, selector)
        .map_err(StorageError::from)
        .map_err(|e| CliError {
            kind: e.into(),
            filename: format!("{path:?}"),
        })
}

pub async fn update_vts(
    redis: &str,
    signature_check: bool,
    args: &clap::ArgMatches,
) -> Result<(), CliError> {
    let path = get_vts_path("vts-path", args);
    let dispatcher = get_dispatcher(redis, &path, FEEDUPDATE_SELECTOR)?;
    update::run(dispatcher, path, signature_check).await
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

    let dispatcher = get_dispatcher(redis, &path, NOTUSUPDATE_SELECTOR)?;
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
    let (args, verbose) = crate::get_args_set_logging(root, "feed")?;
    match args.subcommand() {
        Some(("update", args)) => update(args).await,
        Some(("transform", args)) => {
            let path = get_vts_path("path", args);

            let mut o = ArrayWrapper::new(io::stdout());
            let dispatcher = ItemDispatcher::as_dispatcher(&mut o);
            Some(match update::run(dispatcher, path, false).await {
                Ok(_) => o.end().map_err(StorageError::from).map_err(|se| CliError {
                    filename: "".to_string(),
                    kind: se.into(),
                }),
                Err(e) => Err(e),
            })
        }

        Some(("transpile", args)) => {
            let path = get_vts_path("path", args);
            let rules = match args.get_one::<PathBuf>("rules").cloned() {
                Some(x) => x,
                None => unreachable!("rules is set to required"),
            };

            #[derive(serde::Deserialize, serde::Serialize)]
            struct Wrapper {
                cmds: Vec<ReplaceCommand>,
            }

            let rules = std::fs::read_to_string(rules).unwrap();
            let rules: Wrapper = toml::from_str(&rules).unwrap();
            let rules = rules.cmds;
            let base = path.to_str().unwrap_or_default();
            for r in FeedReplacer::new(base, &rules) {
                let name = r.unwrap();
                if let Some((name, content)) = name {
                    use std::io::Write;
                    let f = std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(&name)
                        .map_err(|e| {
                            let kind = CliErrorKind::Corrupt(format!("unable to open {name}: {e}"));
                            CliError {
                                filename: name.clone(),
                                kind,
                            }
                        });
                    match f.and_then(|mut f| {
                        f.write_all(content.as_bytes()).map_err(|e| {
                            let kind =
                                CliErrorKind::Corrupt(format!("unable to write {name}: {e}"));
                            CliError {
                                filename: name.clone(),
                                kind,
                            }
                        })
                    }) {
                        Ok(_) => {}
                        Err(e) => {
                            return Some(Err(e));
                        }
                    }

                    if verbose > 0 {
                        eprintln!("changed {name}");
                    }
                }
            }
            Some(Ok(()))
        }
        _ => unreachable!("subcommand_required prevents None"),
    }
}
