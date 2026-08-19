// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::stdin;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Subcommand;
use futures::StreamExt;
use scannerlib::alive_test::Scanner as BoreasScanner;
use scannerlib::feed::{HashSumNameLoader, Update};
use scannerlib::models::{self, Host};
use scannerlib::nasl::nasl_std_executor;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::utils::scan_ctx::{NotusCtx, Target};
use scannerlib::notus::{Notus, ProductLoader};
use scannerlib::scanner::preferences::preference::ScanPrefs;
use scannerlib::scanner::{Scan, ScanRunner};
use scannerlib::scheduling::Scheduler;
use scannerlib::storage::inmemory::InMemoryStorage;
use tokio::sync::mpsc;
use tracing::{info, warn, warn_span};

use crate::utils::{ArgOrStdin, NotusArgs};
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
    /// KB key value.
    #[clap(short, long = "kb")]
    kb: Vec<String>,
    /// TCP Ports to scan.
    #[clap(short, long = "port")]
    ports: Vec<u16>,
    /// UDP Ports to scan.
    #[clap(short, long = "udp-port")]
    udp_ports: Vec<u16>,
    #[clap(long = "timeout")]
    timeout: Option<u32>,
    #[clap(long = "vendor")]
    vendor_version: Option<String>,
    /// Notus configuration. Use "<URL>" to connect to a running Skiron
    /// instance or "<PATH>" to product files to use the internal
    /// implementation. If not given Notus will be disabled.
    #[clap(short, long = "notus-url")]
    notus_url: Option<NotusArgs>,
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
    /// Notus configuration. Use "<URL>" to connect to a Notus endpoint of a
    /// running Skiron instance or "<PATH>" to product files to use the
    /// internal implementation. If not given Notus will be disabled.
    #[clap(short, long = "notus-url")]
    notus: Option<NotusArgs>,
}

pub async fn run(args: ExecuteArgs) -> Result<(), CliError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

    let loader = Loader::from_feed_path(args.path);
    let verifier = HashSumNameLoader::sha256(&loader)?;
    let updater = Update::init("1", 5, loader.clone(), &storage, verifier);
    updater.perform_update().await?;

    let vts_cloned = scan.vts.clone();
    let scheduler = Scheduler::new(storage.clone());
    let schedule = scheduler
        .execution_plan(&vts_cloned)
        .await
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
        let executor = nasl_std_executor();
        let scan = Scan::default_to_localhost(scan);
        let notus = args.notus.map(|x| match x {
            NotusArgs::Address(addr) => NotusCtx::Address(addr),
            NotusArgs::Internal(path) => NotusCtx::Direct(Arc::new(Mutex::new(Notus::new(
                // we don't require a correctly setup feed for scannerctl
                ProductLoader::new(false, Loader::from_feed_path(path)),
            )))),
        });

        let host_by_ip: HashMap<String, Target> = scan
            .targets
            .iter()
            .map(|t| (t.ip_addr().to_string(), t.clone()))
            .collect();
        let host_set: HashSet<Host> = host_by_ip.keys().cloned().collect();
        let methods = scan.alive_test_methods.clone();
        let capacity = host_by_ip.len().max(1);

        // This channel is for sending a target to the running scan.
        let (tx_target, rx_target) = mpsc::channel::<Target>(capacity);
        // This channel receives alive host from the alive test scanner
        let (tx_host, mut rx_host) = mpsc::channel::<Host>(capacity);

        // Resolves every host reported alive to its `Target` and forwards
        // it to the running scan so it can start scanning it right away.
        tokio::spawn(async move {
            while let Some(host) = rx_host.recv().await {
                if let Some(target) = host_by_ip.get(&host)
                    && tx_target.send(target.clone()).await.is_err()
                {
                    break;
                }
            }
            // Dropping `tx_target` here closes the channel, signalling to
            // the running scan that no further hosts will arrive.
        });

        tokio::spawn(async move {
            let alive_scanner = BoreasScanner::new(host_set.clone(), methods, None);
            let alive = alive_scanner
                .run_alive_test_streaming(Some(tx_host))
                .await
                .unwrap_or_default();
            let dead: Vec<String> = host_set.difference(&alive).cloned().collect();
            if !dead.is_empty() {
                info!("Dead hosts: {:?}", &dead);
            }
        });

        // TODO: fix this standalone scanner. It loads the feed but no result is shown
        let runner: ScanRunner<Arc<InMemoryStorage>> = ScanRunner::new(
            &storage, &loader, &executor, schedule, &scan, &notus, rx_target,
        )
            .unwrap();
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
    let notus = args.notus_url.map(|x| match x {
        NotusArgs::Address(addr) => NotusCtx::Address(addr),
        NotusArgs::Internal(path) => NotusCtx::Direct(Arc::new(Mutex::new(Notus::new(
            // scannerctl doesn't require a proper feed
            ProductLoader::new(false, Loader::from_feed_path(path)),
        )))),
    });
    let scan_preferences = ScanPrefs::new()
        .set_default_recv_timeout(args.timeout)
        .set_vendor_version(args.vendor_version);
    interpret::run(
        &Db::InMemory,
        args.feed_path,
        &args.script,
        args.target.clone(),
        args.kb.clone(),
        args.ports.clone(),
        args.udp_ports.clone(),
        scan_preferences,
        notus,
    )
    .await
}
