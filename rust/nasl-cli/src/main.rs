// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#![doc = include_str!("../README.md")]
mod error;
mod feed_update;
mod interpret;
mod scanconfig;
mod syntax_check;

use configparser::ini::Ini;
pub use error::*;

use std::{
    io::{self},
    path::PathBuf,
    process,
};
use storage::StorageError;

use clap::{arg, value_parser, Arg, ArgAction, Command};

#[derive(Debug)]
enum Commands {
    /// Checks nasl-file or a directory of for syntax errors.
    Syntax {
        /// The path for the file or dir to parse
        path: PathBuf,
        /// Disables printing of progress
        no_progress: bool,
        /// Verbose output
        verbose: bool,
    },
    /// Controls the feed
    Feed {
        /// The action to perform on a feed
        action: FeedAction,
    },
    /// Executes a script
    Execute {
        db: Db,
        feed: Option<PathBuf>,
        script: String,
        target: Option<String>,
    },
    /// Transforms a scan config to scan json for openvasd
    ScanConfig {
        feed: Option<PathBuf>,
        config: Vec<String>,
        port_list: Option<String>,
        stdin: bool,
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
        /// If the signature check of the sha256sums file must be performed.
        signature_check: Option<bool>,
    },
    /// Transforms the feed into stdout
    ///
    Transform {
        /// The path to the NASL plugins.
        ///
        /// When it is skipped it will be obtained via `openvas -s`
        path: Option<PathBuf>,
    },
    /// Transpiles the feed based on a given ruleset.
    ///
    Transpile {
        /// The path to the NASL plugins.
        ///
        path: PathBuf,
        /// Describes the rules for changing the rules.
        ///
        /// The rules describe how to find a certain element and how to replace it.
        /// Currently only toml in the following format is supported:
        /// ```toml
        /// [[cmds]]
        ///
        /// [cmds.find]
        /// FunctionByName = "register_host_detail"
        ///
        /// [cmds.with]
        /// Name = "add_host_detail"
        /// ```
        rules: PathBuf,
        /// Prints the changed file names
        verbose: bool,
    },
}

trait RunAction<T> {
    type Error;
    fn run(&self) -> Result<T, Self::Error>;
}

impl RunAction<()> for FeedAction {
    type Error = CliError;
    fn run(&self) -> Result<(), Self::Error> {
        match self {
            FeedAction::Update {
                redis: _,
                path,
                signature_check: _,
            } => {
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
                feed_update::run(
                    dispatcher,
                    update_config.plugin_path,
                    update_config.check_enabled,
                )
            }
            FeedAction::Transform { path } => {
                let transform_config: TransformConfiguration =
                    self.as_config().map_err(|kind| CliError {
                        filename: format!("{path:?}"),
                        kind,
                    })?;

                let mut o = json_storage::ArrayWrapper::new(io::stdout());
                let dispatcher = json_storage::NvtDispatcher::as_dispatcher(&mut o);
                match feed_update::run(dispatcher, transform_config.plugin_path, false) {
                    Ok(_) => o.end().map_err(StorageError::from).map_err(|se| CliError {
                        filename: "".to_string(),
                        kind: se.into(),
                    }),
                    Err(e) => Err(e),
                }
            }
            FeedAction::Transpile {
                path,
                rules,
                verbose,
            } => {
                #[derive(serde::Deserialize, serde::Serialize)]
                struct Wrapper {
                    cmds: Vec<feed::transpile::ReplaceCommand>,
                }

                let rules = std::fs::read_to_string(rules).unwrap();
                let rules: Wrapper = toml::from_str(&rules).unwrap();
                let rules = rules.cmds;
                let base = path.to_str().unwrap_or_default();
                for r in feed::transpile::FeedReplacer::new(base, &rules) {
                    let name = r.unwrap();
                    if let Some((name, content)) = name {
                        use std::io::Write;
                        let mut f = std::fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&name)
                            .map_err(|e| {
                                let kind =
                                    CliErrorKind::Corrupt(format!("unable to open {name}: {e}"));
                                CliError {
                                    filename: name.clone(),
                                    kind,
                                }
                            })?;
                        f.write_all(content.as_bytes()).map_err(|e| {
                            let kind =
                                CliErrorKind::Corrupt(format!("unable to write {name}: {e}"));
                            CliError {
                                filename: name.clone(),
                                kind,
                            }
                        })?;

                        if *verbose {
                            eprintln!("changed {name}");
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

impl RunAction<()> for Commands {
    type Error = CliError;
    fn run(&self) -> Result<(), Self::Error> {
        match self {
            Commands::Syntax {
                path,
                no_progress,
                verbose,
            } => syntax_check::run(path, *verbose, *no_progress),
            Commands::Feed { action } => action.run(),
            Commands::Execute {
                db,
                feed,
                script,
                target,
            } => interpret::run(db, feed.clone(), script.to_string(), target.clone()),
            Commands::ScanConfig {
                feed,
                config,
                port_list,
                stdin,
            } => scanconfig::run(feed.as_ref(), config, port_list.as_ref(), *stdin),
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
    check_enabled: bool,
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
                signature_check: Some(check_enabled),
            } => Ok(FeedUpdateConfiguration {
                redis_url,
                plugin_path,
                check_enabled,
            }),
            FeedAction::Update {
                redis,
                path,
                signature_check,
            } => {
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

                let check_enabled = {
                    if let Some(c) = signature_check {
                        c
                    } else {
                        false
                    }
                };

                Ok(FeedUpdateConfiguration {
                    plugin_path,
                    redis_url,
                    check_enabled,
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
        .about("Is a CLI tool around NASL.")
        .arg(arg!(-v --verbose ... "Prints more details while running").required(false).action(ArgAction::Count))
        .arg(arg!(-vv --very-verbose ... "Prints even more details while running").required(false).action(ArgAction::SetTrue))
        .subcommand_required(true)
        .subcommand(
            Command::new("feed")
                .about("Handles feed related tasks")
                .subcommand_required(true)
                .subcommand(Command::new("update")
                .about("Runs nasl scripts in description mode and updates data into redis")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                .arg(arg!(-x --"signature-check" "Enable NASL signature check.") .required(false).action(ArgAction::SetTrue))
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
                .arg(arg!(-t --target <HOST> "Target to scan") .required(false))
        )
        .subcommand(
            Command::new("scan-config")
                .about("Transforms a scan-config xml to a scan json for openvasd.
When piping a scan json it is enriched with the scan-config xml and may the portlist otherwise it will print a scan json without target or credentials.")
                .arg(arg!(-p --path <FILE> "Path to the feed.") .required(false)
                    .value_parser(value_parser!(PathBuf)))
                .arg(Arg::new("scan-config").required(true).action(ArgAction::Append))
                .arg(arg!(-i --input "Parses scan json from stdin.").required(false).action(ArgAction::SetTrue))
                .arg(arg!(-l --portlist <FILE> "Path to the port list xml") .required(false))
        )
.get_matches();
    let verbose = matches
        .get_one::<u8>("verbose")
        .cloned()
        .unwrap_or_default();
    let lv = if verbose > 1 {
        tracing::Level::TRACE
    } else if verbose > 0 {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(lv)
        .init();
    let command = match matches.subcommand() {
        Some(("feed", args)) => match args.subcommand() {
            Some(("update", args)) => {
                let path = args.get_one::<PathBuf>("path").cloned();
                let redis = args.get_one::<String>("redis").cloned();
                let signature_check = args.get_one::<bool>("signature-check").cloned();
                Commands::Feed {
                    action: FeedAction::Update {
                        redis,
                        path,
                        signature_check,
                    },
                }
            }
            Some(("transform", args)) => {
                let path = args.get_one::<PathBuf>("path").cloned();
                Commands::Feed {
                    action: FeedAction::Transform { path },
                }
            }

            Some(("transpile", args)) => {
                let path = match args.get_one("path").cloned() {
                    Some(x) => x,
                    None => unreachable!("path is set to required"),
                };
                let rules = match args.get_one("rules").cloned() {
                    Some(x) => x,
                    None => unreachable!("rules is set to required"),
                };
                Commands::Feed {
                    action: FeedAction::Transpile {
                        path,
                        rules,
                        verbose: verbose > 0,
                    },
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
                verbose: verbose > 0,
                no_progress: quiet,
            }
        }
        Some(("execute", args)) => {
            let feed = args.get_one::<PathBuf>("path").cloned();
            let script = match args.get_one::<String>("script").cloned() {
                Some(path) => path,
                _ => unreachable!("path is set to required"),
            };
            let target = args.get_one::<String>("target").cloned();

            Commands::Execute {
                db: Db::InMemory,
                feed,
                script,
                target,
            }
        }
        Some(("scan-config", args)) => {
            let feed = args.get_one::<PathBuf>("path").cloned();
            let config = args
                .get_many::<String>("scan-config")
                .expect("scan-config is required")
                .cloned()
                .collect();
            let port_list = args.get_one::<String>("portlist").cloned();
            tracing::debug!("port_list: {port_list:?}");
            let stdin = args.get_one::<bool>("input").cloned().unwrap_or_default();
            Commands::ScanConfig {
                feed,
                config,
                port_list,
                stdin,
            }
        }
        _ => unreachable!("subcommand_required prevents None"),
    };

    match command.run() {
        Ok(_) => {}
        Err(e) => match e.kind {
            CliErrorKind::StorageError(StorageError::UnexpectedData(x)) => match &x as &str {
                "BrokenPipe" => {}
                _ => panic!("Unexpected data within dispatcher: {x}"),
            },
            CliErrorKind::InterpretError(_) | CliErrorKind::SyntaxError(_) => {
                tracing::warn!("script error, {e}");
                std::process::exit(1);
            }
            _ => panic!("{e}"),
        },
    }
}
