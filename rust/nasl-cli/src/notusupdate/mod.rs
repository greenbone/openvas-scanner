pub mod update;
use std::path::PathBuf;

use clap::{arg, value_parser, ArgAction, Command};
// re-export to work around name conflict

use redis_storage::NOTUSUPDATE_SELECTOR;
use storage::StorageError;

use crate::{read_openvas_config, CliError};

pub fn extend_args(cmd: Command) -> Command {
    crate::add_verbose(
    cmd.subcommand(
            Command::new("notus")
                .about("Handles notus advisories update")
                .subcommand_required(true)
                .subcommand(Command::new("update")
                .about("Updates notus data into redis")
                .arg(arg!(-p --path <DIR> "Path to the notus advisories.") .required(true)
                    .value_parser(value_parser!(PathBuf)))
                .arg(arg!(-x --"signature-check" "Enable NASL signature check.") .required(false).action(ArgAction::SetTrue))
                .arg(arg!(-r --redis <VALUE> "Redis url. Must either start `unix://` or `redis://`.").required(false))
                )
        ))
}

pub fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _verbose) = crate::get_args_set_logging(root, "notus")?;
    match args.subcommand() {
        Some(("update", args)) => {
            let path = args.get_one::<PathBuf>("path").unwrap().to_path_buf();

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

            let dispatcher =
                redis_storage::NvtDispatcher::as_dispatcher(&redis, NOTUSUPDATE_SELECTOR)
                    .map_err(StorageError::from)
                    .map_err(|e| CliError {
                        kind: e.into(),
                        filename: format!("{path:?}"),
                    });
            Some(dispatcher.and_then(|dispatcher| update::run(dispatcher, path, signature_check)))
        }
        _ => unreachable!("subcommand_required prevents None"),
    }
}
