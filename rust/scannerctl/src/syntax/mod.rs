// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::PathBuf;

use clap::{arg, value_parser, Arg, ArgAction, Command};

use crate::{add_verbose, CliError};

pub mod check;

pub fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, verbose) = crate::get_args_set_logging(root, "syntax")?;
    let path = match args.get_one::<PathBuf>("path").cloned() {
        Some(path) => path,
        _ => unreachable!("path is set to required"),
    };
    let quiet = args.get_one::<bool>("quiet").cloned().unwrap_or_default();

    Some(check::run(&path, verbose > 0, quiet))
}

pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand(add_verbose(
        Command::new("syntax")
            .about("Verifies syntax of NASL files in given dir or file.")
            .arg(
                Arg::new("path")
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(-q --quiet "Prints only error output and no progress.")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
    ))
}
