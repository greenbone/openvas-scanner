// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fs::File;
use std::io::stdin;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Subcommand;
use futures::StreamExt;
use scannerlib::feed::{HashSumNameLoader, Update};
use scannerlib::models;
use scannerlib::nasl::{FSPluginLoader, nasl_std_functions};
use scannerlib::scanner::{Scan, ScanRunner};
use scannerlib::scheduling::{ExecutionPlaner, WaveExecutionPlan};
use scannerlib::storage::inmemory::InMemoryStorage;
use tracing::{info, warn, warn_span};

use crate::utils::ArgOrStdin;
use crate::{CliError, CliErrorKind, Db, interpret};

#[derive(clap::Parser)]
pub struct ExecuteArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    Script(ScriptArgs),
    Scan(ScanArgs),
}

#[derive(clap::Parser)]
struct ScriptArgs {
    script: PathBuf,
    /// The path to the feed.
    #[clap(short, long)]
    feed_path: Option<PathBuf>,
    /// Target to scan.
    #[clap(short, long)]
    target: Option<String>,
}

#[derive(clap::Parser)]
struct ScanArgs {
    /// The path to the feed.
    path: PathBuf,
    /// Path to the scan config JSON. Use "-" to read from stdin.
    json: ArgOrStdin<PathBuf>,
    /// Print the schedule without executing the scan.
    #[clap(short, long)]
    schedule_only: bool,
    /// Target to scan.
    #[clap(short, long)]
    target: Option<String>,
}

pub async fn run(args: ExecuteArgs) -> Result<(), CliError> {
    match args.action {
        Action::Script(args) => script(args).await,
        Action::Scan(args) => scan(args).await,
    }
}

async fn scan(args: ScanArgs) -> Result<(), CliError> {
    let scan: models::Scan = match args.json {
        ArgOrStdin::Arg(f) => serde_json::from_reader(File::open(f)?)
            .map_err(|e| CliErrorKind::Corrupt(format!("{e:?}")))?,
        ArgOrStdin::Stdin => {
            serde_json::from_reader(stdin()).map_err(|e| CliErrorKind::Corrupt(format!("{e:?}")))?
        }
    };
    let storage = Arc::new(InMemoryStorage::new());
    info!("loading feed. This may take a while.");

    let loader = FSPluginLoader::new(args.path);
    let verifier = HashSumNameLoader::sha256(&loader)?;
    let updater = Update::init("1", 5, &loader, &storage, verifier);
    updater.perform_update().await?;

    let vts_cloned = scan.vts.clone();
    let schedule = storage
        .execution_plan::<WaveExecutionPlan>(&vts_cloned)
        .expect("expected to be schedulable");
    info!("creating scheduling plan");
    if args.schedule_only {
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
        let scan = Scan::default_to_localhost(scan);
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

async fn script(args: ScriptArgs) -> Result<(), CliError> {
    interpret::run(
        &Db::InMemory,
        args.feed_path,
        &args.script,
        args.target.clone(),
    )
    .await
}
