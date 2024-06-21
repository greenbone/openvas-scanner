// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::PathBuf;

use clap::{arg, value_parser, Arg, Command};

use crate::{interpret, CliError, Db};

pub fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "execute")?;
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
    ))
}
