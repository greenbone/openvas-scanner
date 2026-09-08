// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Subcommand;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::utils::scan_ctx::NotusCtx;
use scannerlib::notus::{Notus, ProductLoader};
use scannerlib::scanner::preferences::preference::ScanPrefs;

use crate::utils::NotusArgs;
use crate::{CliError, Db, interpret};

#[derive(clap::Parser)]
pub struct ExecuteArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    Script(ScriptArgs),
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

pub async fn run(args: ExecuteArgs) -> Result<(), CliError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    match args.action {
        Action::Script(args) => script(args).await,
    }
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
