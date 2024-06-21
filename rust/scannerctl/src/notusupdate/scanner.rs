// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    io,
    path::{Path, PathBuf},
};

use clap::{arg, value_parser, Arg, ArgAction, Command};
use notus::{loader::fs::FSProductLoader, notus::Notus};

use crate::CliError;

pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand(crate::add_verbose(
        Command::new("notus")
            .about("does use notus products to compare packages against known vulnerabilities.")
            .arg(
                arg!(-p --path <FILE> "Path to the product feed.")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(-i --input "comma separated pkg list from stdin.")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                arg!(-l --"pkg-list" <STRING> "Comma separated list of packages.")
                    .required_unless_present("input"),
            )
            .arg(Arg::new("os").required(true).action(ArgAction::Append)),
    ))
}

pub fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "notus")?;
    let products_path = args.get_one::<PathBuf>("path").unwrap();

    let stdin = args.get_one::<bool>("input").cloned().unwrap_or_default();

    let os = args.get_one::<String>("os").unwrap();
    let pkg_list = args.get_one::<String>("pkg-list");
    Some(execute(
        pkg_list.map(|x| x as &str),
        os,
        products_path,
        stdin,
    ))
}

fn execute<T>(
    pkg_list: Option<&str>,
    os: &str,
    products_path: T,
    stdin: bool,
) -> Result<(), CliError>
where
    T: AsRef<Path>,
{
    let loader = FSProductLoader::new(products_path)?;
    let buf = if stdin {
        io::read_to_string(io::stdin())?
    } else {
        pkg_list.unwrap_or("").to_string()
    };
    let packages = buf.split(',').map(String::from).collect::<Vec<_>>();

    let mut notus = Notus::new(loader, false);
    tracing::debug!(?packages, "going to scan");
    serde_json::to_writer_pretty(io::stdout(), &notus.scan(os, &packages)?)?;
    Ok(())
}
