// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
mod error;
mod execute;
mod feed;
mod interpret;
mod notusupdate;
mod osp;
mod scan_config;
mod syntax;

use configparser::ini::Ini;
pub use error::*;

use osp::OspArgs;
use scan_config::ScanConfigArgs;
use scannerlib::storage::StorageError;
use std::{path::PathBuf, process};
use syntax::SyntaxArgs;

use clap::{arg, ArgAction, ArgMatches, Command, Parser};

#[derive(Debug, Clone)]
pub enum Db {
    Redis(String),
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
enum Args {
    Syntax(SyntaxArgs),
    ScanConfig(ScanConfigArgs),
    Osp(OspArgs),
    // Execute(ExecuteArgs),
    // Notusupdate(NotusupdateArgs),
    // Feed(FeedArgs),
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // let matches = add_verbose(
    //     Command::new("scannerctl")
    //         .version("1.0")
    //         .about("Is a CLI tool around NASL.")
    //         .subcommand_required(true),
    // );
    // let matches = scan_config::extend_args(matches);
    // let matches = osp::extend_args(matches);
    // let matches = execute::extend_args(matches);
    // let matches = notusupdate::scanner::extend_args(matches);
    // let matches = feed::extend_args(matches).get_matches();
    let result = run(args).await;

    match result {
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

async fn run(args: Args) -> Result<(), CliError> {
    let sub_verbosity = match &args {
        Args::Syntax(args) => Some(args.verbose),
        Args::ScanConfig(args) => Some(args.verbose),
        Args::Osp(args) => None,
    };
    match args {
        Args::Syntax(args) => syntax::run(args).await?,
        Args::ScanConfig(args) => scan_config::run(args).await?,
        Args::Osp(args) => osp::run(args).await?,
    }
    // if let Some(result) = feed::run(matches).await {
    //     return result;
    // }
    // if let Some(result) =  {
    //     return result;
    // }
    // if let Some(result) = execute::run(matches).await {
    //     return result;
    // }
    // if let Some(result) = scan_config::run(matches).await {
    //     return result;
    // }
    // if let Some(result) = notusupdate::scanner::run(matches).await {
    //     return result;
    // }
    // if let Some(result) = osp::run(matches).await {
    //     return result;
    // }
    todo!()
    // Err(CliError {
    //     filename: "".to_string(),
    //     kind: CliErrorKind::Corrupt(format!(
    //         "No valid subcommand found: {:?}",
    //         matches.subcommand()
    //     )),
    // })
}

pub fn set_logging(level: u8) {
    let lv = if level > 1 {
        tracing::Level::TRACE
    } else if level > 0 {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(lv)
        .init();
}

pub fn add_verbose(cmd: Command) -> Command {
    cmd.arg(
        arg!(-v --verbose ... "Prints more details while running")
            .required(false)
            .action(ArgAction::Count),
    )
}

pub fn get_args_set_logging<'a>(
    root: &'a ArgMatches,
    name: &'a str,
) -> Option<(&'a ArgMatches, u8)> {
    let verbose = root.get_one::<u8>("verbose").cloned().unwrap_or_default();
    let args = root.subcommand_matches(name)?;
    let verbose = args.get_one::<u8>("verbose").cloned().unwrap_or(verbose);
    set_logging(verbose);
    Some((args, verbose))
}
