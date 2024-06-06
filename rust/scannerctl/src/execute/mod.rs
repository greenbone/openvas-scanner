// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{fs, io::BufReader, path::PathBuf, sync::Arc};

use clap::{arg, value_parser, Arg, ArgAction, Command};
use storage::Retriever;

use crate::{interpret, CliError, CliErrorKind, Db};

pub fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "execute")?;
    match args.subcommand() {
        Some(("script", args)) => script(args),
        Some(("scan", args)) => Some(scan(args)),
        Some((x, _)) => panic!("Unknown subcommand{}", x),
        None => {
            tracing::warn!("`scannerctl execute` without subcommand is deprecrated and may be removed in the next versions");
            script(args)
        }
    }
}

fn scan(args: &clap::ArgMatches) -> Result<(), CliError> {
    let stdin = args.get_one::<bool>("input").cloned().unwrap_or_default();
    let scan = if stdin {
        tracing::debug!("reading scan config from stdin");
        serde_json::from_reader(std::io::stdin()).map_err(|e| CliError {
            filename: "".to_string(),
            kind: CliErrorKind::Corrupt(format!("{e:?}")),
        })?
    } else {
        let path = args
            .get_one::<PathBuf>("json")
            .cloned()
            .expect("when stdin is set to false a json file is required.");
        tracing::debug!(?path, "reading scan config");
        serde_json::from_reader(fs::File::open(path)?).map_err(|e| CliError {
            filename: "".to_string(),
            kind: CliErrorKind::Corrupt(format!("{e:?}")),
        })?
    };
    let schedule_only = args
        .get_one::<bool>("schedule")
        .cloned()
        .unwrap_or_default();

    let feed = args
        .get_one::<PathBuf>("path")
        .expect("A feed path is required to run a scan");
    let storage = Arc::new(storage::DefaultDispatcher::new(true));
    tracing::info!("loading feed. This may take a while.");
    crate::feed::update::run(Arc::clone(&storage), feed.to_owned(), false)?;
    tracing::info!("feed loaded.");
    use nasl_interpreter::scheduling::ExecutionPlaner;
    // TODO create wrapper for CliError
    tracing::info!("creating scheduling plan");
    let schedule = (storage.as_ref() as &dyn Retriever)
        .execution_plan::<nasl_interpreter::scheduling::WaveExecutionPlan>(&scan)
        .expect("expected to be schedulable");
    if schedule_only {
        for  (i, r) in schedule.enumerate(){
            let (stage, vts) = r.expect("should be resolvable");
            print!("{i} - {stage}:\t");
            println!("{}", vts.into_iter().map(|(vt, _)|vt.oid).collect::<Vec<_>>().join(", "));
        }


    } else {
        todo!("Scan execution is not implemanted yet")

    }


    Ok(())
}
fn script(args: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let feed = args.get_one::<PathBuf>("path").cloned();
    let script = match args.get_one::<String>("script").cloned() {
        Some(path) => path,
        _ => unreachable!("path is set to required"),
    };
    let target = args.get_one::<String>("target").cloned();
    Some(interpret::run(
        &Db::InMemory,
        feed.clone(),
        script.to_string(),
        target.clone(),
    ))
}
pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand(crate::add_verbose(
        Command::new("execute")
            .about("Executes either a script or scan.")
            .subcommand(
                Command::new("script")
                    .about(
                        "Executes a nasl-script.
A script can either be a file to be executed or an ID.
When ID is used than a valid feed path must be given within the path parameter.",
                    )
                    .arg(
                        arg!(-p --path <FILE> "Path to the feed.")
                            .required(false)
                            .value_parser(value_parser!(PathBuf)),
                    )
                    .arg(Arg::new("script").required(true))
                    .arg(arg!(-t --target <HOST> "Target to scan").required(false)),
            )
            .subcommand(
                Command::new("scan")
                    .about(
                        "Executes a scan. A scan can either be provided by a file via the path parameter or via stdin.",
                    )
                    .arg(
                        arg!(-p --path <FILE> "Path to the feed.")
                            .required(true)
                            .value_parser(value_parser!(PathBuf)),
                    )
                    .arg(arg!(--schedule "Prints just the schedule without executing the scan").required(false).action(ArgAction::SetTrue))
                    .arg(arg!(-i --input "Parses scan json from stdin.").required(false).action(ArgAction::SetTrue))
                    .arg(Arg::new("json").required(false))
            )
            // this is here for downwards compatible reasons and should be moved to the script
            // subcommand without allowing it on root as well.
            .arg(
                arg!(-p --path <FILE> "Path to the feed.")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(Arg::new("script").required(false))
            .arg(arg!(-t --target <HOST> "Target to scan").required(false)),
    ))
}
