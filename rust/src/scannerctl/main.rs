// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
// We allow this fow now, since it would require lots of changes
// but should eventually solve this.
#![allow(clippy::result_large_err)]

#[cfg(feature = "nasl-builtin-raw-ip")]
mod alivetest;
mod error;
mod execute;
mod feed;
mod interpret;
mod notus_update;
mod osp;
mod scan_config;
mod syntax;
mod utils;

use configparser::ini::Ini;
use error::*;

use execute::ExecuteArgs;
use feed::FeedArgs;
use notus_update::scanner::NotusUpdateArgs;
use osp::OspArgs;
use scan_config::ScanConfigArgs;
use scannerlib::storage::error::StorageError;
use std::{path::PathBuf, process};
use syntax::SyntaxArgs;
use tracing::Level;

use clap::{Parser, Subcommand, arg};

#[derive(Debug, Clone)]
enum Db {
    InMemory,
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

fn get_path_from_openvas(config: Ini) -> PathBuf {
    PathBuf::from(
        config
            .get("default", "plugins_folder")
            .expect("openvas -s must contain plugins_folder"),
    )
}

#[derive(clap::Parser)]
/// A CLI tool providing NASL-related functionality.
struct Args {
    /// Print more details while running
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Print only error output.
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    Syntax(SyntaxArgs),
    ScanConfig(ScanConfigArgs),
    Osp(OspArgs),
    Execute(ExecuteArgs),
    NotusUpdate(NotusUpdateArgs),
    Feed(FeedArgs),
    #[cfg(feature = "nasl-builtin-raw-ip")]
    Alivetest(alivetest::AliveTestArgs),
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    set_logging(args.verbose, args.quiet);
    let result = run(args.action, args.verbose > 0, args.quiet).await;

    match result {
        Ok(_) => {}
        Err(e) => match e.kind {
            CliErrorKind::StorageError(StorageError::UnexpectedData(x)) => match &x as &str {
                "BrokenPipe" => {}
                _ => panic!("Unexpected data within dispatcher: {x}"),
            },
            CliErrorKind::InterpretError(_) | CliErrorKind::SyntaxError(_) => {
                std::process::exit(1);
            }
            CliErrorKind::InvalidCmdOpt(_) => {
                tracing::warn!("Command line option error, {e}");
                std::process::exit(1);
            }
            _ => panic!("{e}"),
        },
    }
}

async fn run(action: Action, verbose: bool, quiet: bool) -> Result<(), CliError> {
    match action {
        Action::Syntax(args) => syntax::run(args, verbose, quiet).await,
        Action::ScanConfig(args) => scan_config::run(args).await,
        Action::Osp(args) => osp::run(args).await,
        Action::Execute(args) => execute::run(args).await,
        Action::NotusUpdate(args) => notus_update::scanner::run(args).await,
        Action::Feed(args) => feed::run(args).await,
        #[cfg(feature = "nasl-builtin-raw-ip")]
        Action::Alivetest(args) => alivetest::run(args).await,
    }
}

fn set_logging(level: u8, quiet: bool) {
    let level = match level {
        level if level > 1 => Level::TRACE,
        1 => Level::DEBUG,
        0 => Level::INFO,
        _ => {
            if quiet {
                Level::ERROR
            } else {
                Level::INFO
            }
        }
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .init();
}
