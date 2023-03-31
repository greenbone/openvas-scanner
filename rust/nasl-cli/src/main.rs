// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later
#![doc = include_str!("../README.md")]
mod error;
mod feed_update;
mod interpret;
mod syntax_check;

use configparser::ini::Ini;
pub use error::*;

use std::{io, path::PathBuf, process};
use storage::StorageError;

use clap::{arg, value_parser, Arg, ArgAction, Command};

#[derive(Debug)]
enum Commands {
    /// Checks nasl-file or a directory of for syntax errors.
    Syntax {
        /// The path for the file or dir to parse
        path: PathBuf,
        /// Prints all parsed statements instead of just errors
        verbose: bool,
        /// Disables printing of progress
        no_progress: bool,
    },
    /// Controls the feed
    Feed {
        /// Prints the interpret filename and elapsed time for each
        verbose: bool,
        /// The action to perform on a feed
        action: FeedAction,
    },
    Execute {
        db: Db,
        feed: Option<PathBuf>,
        script: String,
    },
}

#[derive(Debug, Clone)]
pub enum Db {
    Redis(String),
    InMemory,
}

#[derive(Debug, Clone)]
enum FeedAction {
    /// Updates feed data into redis.
    Update {
        /// Redis address inform of tcp (redis://) or unix socket (unix://).
        ///
        /// It must be the complete redis address in either the form of a unix socket or tcp.
        /// For tcp provide the address in the form of: `redis://host:port`.
        /// For unix socket provide the path to the socket in the form of: `unix://path/to/redis.sock`.
        /// When it is skipped it will be obtained via `openvas -s`
        redis: Option<String>,
        /// The path to the NASL plugins.
        ///
        /// When it is skipped it will be obtained via `openvas -s`
        path: Option<PathBuf>,
    },
    /// Transforms the feed into stdout
    ///
    Transform {
        /// The path to the NASL plugins.
        ///
        /// When it is skipped it will be obtained via `openvas -s`
        path: Option<PathBuf>,
    },
}

trait RunAction<T> {
    type Error;
    fn run(&self, verbose: bool) -> Result<T, Self::Error>;
}

impl RunAction<()> for FeedAction {
    type Error = CliError;
    fn run(&self, verbose: bool) -> Result<(), Self::Error> {
        match self {
            FeedAction::Update { redis: _, path } => {
                let update_config: FeedUpdateConfiguration =
                    self.as_config().map_err(|kind| CliError {
                        filename: String::new(),
                        kind,
                    })?;
                let dispatcher =
                    redis_storage::NvtDispatcher::as_dispatcher(&update_config.redis_url)
                        .map_err(StorageError::from)
                        .map_err(|e| CliError {
                            kind: e.into(),
                            filename: format!("{path:?}"),
                        })?;
                feed_update::run(dispatcher, update_config.plugin_path, verbose)
            }
            FeedAction::Transform { path } => {
                let transform_config: TransformConfiguration =
                    self.as_config().map_err(|kind| CliError {
                        filename: format!("{path:?}"),
                        kind,
                    })?;

                let mut o = json_storage::ArrayWrapper::new(io::stdout());
                let dispatcher = json_storage::NvtDispatcher::as_dispatcher(&mut o);
                match feed_update::run(dispatcher, transform_config.plugin_path, verbose) {
                    Ok(_) => o.end().map_err(StorageError::from).map_err(|se| CliError {
                        filename: "".to_string(),
                        kind: se.into(),
                    }),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

impl RunAction<()> for Commands {
    type Error = CliError;
    fn run(&self, verbose: bool) -> Result<(), Self::Error> {
        match self {
            Commands::Syntax {
                path,
                verbose,
                no_progress,
            } => syntax_check::run(path, *verbose, *no_progress),
            Commands::Feed { verbose, action } => action.run(*verbose),
            Commands::Execute { db, feed, script } => {
                interpret::run(db, feed.clone(), script.to_string(), verbose)
            }
        }
    }
}

trait AsConfig<T> {
    fn as_config(&self) -> Result<T, CliErrorKind>;
}

/// Is the configuration required to run feed related operations.
struct FeedUpdateConfiguration {
    /// Plugin path is required for either
    plugin_path: PathBuf,
    redis_url: String,
}

struct TransformConfiguration {
    plugin_path: PathBuf,
}

fn read_openvas_config() -> Result<Ini, CliErrorKind> {
    let oconfig = process::Command::new("openvas")
        .arg("-s")
        .output()
        .map_err(|e| CliErrorKind::Openvas {
            args: "-s".to_owned().into(),
            err_msg: format!("{e:?}"),
        })?;

    let mut config = Ini::new();
    let oconfig = oconfig.stdout.iter().map(|x| *x as char).collect();
    config.read(oconfig).map_err(|e| CliErrorKind::Openvas {
        args: None,
        err_msg: format!("{e:?}"),
    })?;
    Ok(config)
}

impl AsConfig<TransformConfiguration> for FeedAction {
    fn as_config(&self) -> Result<TransformConfiguration, CliErrorKind> {
        match self {
            FeedAction::Transform { path } => {
                if let Some(path) = path {
                    Ok(TransformConfiguration {
                        plugin_path: path.clone(),
                    })
                } else {
                    let plugin_path = get_path_from_openvas(read_openvas_config()?);
                    Ok(TransformConfiguration { plugin_path })
                }
            }
            _ => unreachable!("only transform can be TransformConfiguration"),
        }
    }
}

impl AsConfig<FeedUpdateConfiguration> for FeedAction {
    fn as_config(&self) -> Result<FeedUpdateConfiguration, CliErrorKind> {
        match self.clone() {
            FeedAction::Update {
                redis: Some(redis_url),
                path: Some(plugin_path),
            } => Ok(FeedUpdateConfiguration {
                redis_url,
                plugin_path,
            }),
            FeedAction::Update { redis, path } => {
                // This is only valid as long as we don't have a proper configuration file and rely on openvas.
                let config = read_openvas_config()?;
                let redis_url = {
                    if let Some(rp) = redis {
                        rp
                    } else {
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

                let plugin_path = {
                    if let Some(p) = path {
                        p
                    } else {
                        get_path_from_openvas(config)
                    }
                };
                Ok(FeedUpdateConfiguration {
                    plugin_path,
                    redis_url,
                })
            }
            _ => unreachable!("only update can be converted to FeedUpdateConfiguration"),
        }
    }
}

fn get_path_from_openvas(config: Ini) -> PathBuf {
    PathBuf::from(
        config
            .get("default", "plugins_folder")
            .expect("openvas -s must contain plugins_folder"),
    )
}

fn main() {
    let matches = Command::new("nasl-cli")
        .version("1.0")
        .about("Is CLI tool around NASL.")
        .arg(arg!(-v --verbose ... "Prints more details while running").required(false).action(ArgAction::SetTrue))
        .subcommand_required(true)
        .subcommand(
            Command::new("feed")
                .about("Handles feed related tasks")
                .subcommand_required(true)
                .subcommand(Command::new("update")
                .about("Runs nasl scripts in description mode and updates data into redis")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                .arg(arg!(-r --redis <VALUE> "Redis url. Must either start `unix://` or `redis://`.").required(false))
                )
                .subcommand(Command::new("transform")
                .about("Runs nasl scripts in description mode and returns it as a json array into stdout")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                )
        )
        .subcommand(
            Command::new("syntax")
                .about("Verifies syntax of NASL files in given dir or file.")
                .arg(Arg::new("path").required(true)
                    .value_parser(value_parser!(PathBuf)))
                .arg(arg!(-q --quiet "Prints only error output and no progress.").required(false).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("execute")
                .about("Executes a nasl-script.
A script can either be a file to be executed or an ID.
When ID is used than a valid feed path must be given within the path parameter.")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                .arg(Arg::new("script").required(true))
        )
        .get_matches();
    let verbose = matches
        .get_one::<bool>("verbose")
        .cloned()
        .unwrap_or_default();
    let command = match matches.subcommand() {
        Some(("feed", args)) => match args.subcommand() {
            Some(("update", args)) => {
                let path = args.get_one::<PathBuf>("path").cloned();
                let redis = args.get_one::<String>("redis").cloned();
                Commands::Feed {
                    verbose,
                    action: FeedAction::Update { redis, path },
                }
            }
            Some(("transform", args)) => {
                let path = args.get_one::<PathBuf>("path").cloned();
                Commands::Feed {
                    verbose,
                    action: FeedAction::Transform { path },
                }
            }
            _ => unreachable!("subcommand_required prevents None"),
        },
        Some(("syntax", args)) => {
            let path = match args.get_one::<PathBuf>("path").cloned() {
                Some(path) => path,
                _ => unreachable!("path is set to required"),
            };
            let quiet = args.get_one::<bool>("quiet").cloned().unwrap_or_default();
            Commands::Syntax {
                path,
                verbose,
                no_progress: quiet,
            }
        }
        Some(("execute", args)) => {
            let feed = args.get_one::<PathBuf>("path").cloned();
            let script = match args.get_one::<String>("script").cloned() {
                Some(path) => path,
                _ => unreachable!("path is set to required"),
            };
            Commands::Execute {
                db: Db::InMemory,
                feed,
                script,
            }
        }
        _ => unreachable!("subcommand_required prevents None"),
    };

    match command.run(verbose) {
        Ok(_) => {}
        Err(e) => match e.kind {
            CliErrorKind::StorageError(StorageError::UnexpectedData(x)) => match &x as &str {
                "BrokenPipe" => {}
                _ => panic!("Unexpected data within dispatcher: {x}"),
            },
            CliErrorKind::InterpretError(_) | CliErrorKind::SyntaxError(_) => {
                eprintln!("script error, {e}");
                std::process::exit(1);
            }
            _ => panic!("{e}"),
        },
    }
}
