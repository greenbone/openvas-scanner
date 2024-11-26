// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{fs, path::PathBuf};

use clap::{arg, value_parser, Arg, ArgAction, Command};
use futures::StreamExt;
use scannerlib::feed::{HashSumNameLoader, Update};
use scannerlib::models::Scan;
use scannerlib::nasl::{nasl_std_functions, FSPluginLoader};
use scannerlib::scanner::ScanRunner;
use scannerlib::scheduling::{ExecutionPlaner, WaveExecutionPlan};
use tracing::{info, warn, warn_span};

use crate::{interpret, CliError, CliErrorKind, Db};

pub async fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "execute")?;
    match args.subcommand() {
        Some(("script", args)) => script(args).await,
        Some(("scan", args)) => Some(scan(args).await),
        Some((x, _)) => panic!("Unknown subcommand{}", x),
        None => {
            warn!("`scannerctl execute` without subcommand is deprecrated and may be removed in the next versions");
            script(args).await
        }
    }
}

async fn scan(args: &clap::ArgMatches) -> Result<(), CliError> {
    let stdin = args.get_one::<bool>("input").cloned().unwrap_or_default();
    let scan: Scan = if stdin {
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
        .expect("A feed path is required to run a scan")
        .clone();
    let storage = scannerlib::storage::DefaultDispatcher::new();
    info!("loading feed. This may take a while.");

    let loader = FSPluginLoader::new(feed);
    let verifier = HashSumNameLoader::sha256(&loader)?;
    let updater = Update::init("1", 5, &loader, &storage, verifier);
    updater.perform_update().await?;

    let schedule = storage
        .execution_plan::<WaveExecutionPlan>(&scan)
        .expect("expected to be schedulable");
    info!("creating scheduling plan");
    if schedule_only {
        for (i, r) in schedule.enumerate() {
            let (stage, vts) = r.expect("should be resolvable");
            print!("{i} - {stage}:\t");
            println!(
                "{}",
                vts.into_iter()
                    .map(|(vt, _)| vt.oid)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    } else {
        let executor = nasl_std_functions();
        let runner: ScanRunner<(_, _)> =
            ScanRunner::new(&storage, &loader, &executor, schedule, &scan).unwrap();
        let mut results = Box::pin(runner.stream());
        while let Some(x) = results.next().await {
            match x {
                Ok(x) => {
                    let _span =
                        warn_span!("script_result", filename=x.filename, oid=x.oid, stage=%x.stage)
                            .entered();
                    if x.has_succeeded() {
                        info!("success")
                    } else {
                        warn!(kind=?x.kind, "failed")
                    }
                }
                Err(e) => {
                    warn!(error=?e, "failed to execute script.");
                }
            }
        }
    }

    Ok(())
}

async fn script(args: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let feed = args.get_one::<PathBuf>("path").cloned();
    let script = args
        .get_one::<String>("script")
        .cloned()
        .expect("script is set to required");
    let target = args.get_one::<String>("target").cloned();
    Some(
        interpret::run(
            &Db::InMemory,
            feed.clone(),
            &script.to_string(),
            target.clone(),
        )
        .await,
    )
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
                    .arg(Arg::new("json").required(false).value_parser(value_parser!(PathBuf)))
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
