pub mod update;
use std::{io, path::PathBuf};

use clap::{arg, value_parser, ArgAction, Command};
// re-export to work around name conflict

use storage::StorageError;

use crate::{get_path_from_openvas, read_openvas_config, CliError, CliErrorKind};

pub fn extend_args(cmd: Command) -> Command {
    crate::add_verbose(
    cmd.subcommand(
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
        ))
}

pub fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    fn get_path(args: &clap::ArgMatches) -> PathBuf {
        args.get_one::<PathBuf>("path").cloned().unwrap_or_else(|| {
            let config =
                read_openvas_config().expect("openvas -s must be executable when path is not set");
            get_path_from_openvas(config)
        })
    }

    let (args, verbose) = crate::get_args_set_logging(root, "feed")?;
    match args.subcommand() {
        Some(("update", args)) => {
            let path = get_path(args);
            let redis = match args.get_one::<String>("redis").cloned() {
                Some(x) => x,
                None => {
                    let config = read_openvas_config()
                        .expect("openvas -s must be executable when path is not set");
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

            let dispatcher = redis_storage::NvtDispatcher::as_dispatcher(&redis)
                .map_err(StorageError::from)
                .map_err(|e| CliError {
                    kind: e.into(),
                    filename: format!("{path:?}"),
                });
            Some(dispatcher.and_then(|dispatcher| update::run(dispatcher, path, signature_check)))
        }
        Some(("transform", args)) => {
            let path = get_path(args);

            let mut o = json_storage::ArrayWrapper::new(io::stdout());
            let dispatcher = json_storage::NvtDispatcher::as_dispatcher(&mut o);
            Some(match update::run(dispatcher, path, false) {
                Ok(_) => o.end().map_err(StorageError::from).map_err(|se| CliError {
                    filename: "".to_string(),
                    kind: se.into(),
                }),
                Err(e) => Err(e),
            })
        }

        Some(("transpile", args)) => {
            let path = get_path(args);
            let rules = match args.get_one::<String>("rules").cloned() {
                Some(x) => x,
                None => unreachable!("rules is set to required"),
            };

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
