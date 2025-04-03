// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::PathBuf;

use crate::CliError;

pub mod check;

#[derive(clap::Parser)]
pub struct SyntaxArgs {
    /// The directory of the NASL files for which to check the syntax.
    path: PathBuf,
}

pub async fn run(args: SyntaxArgs, verbose: bool, quiet: bool) -> Result<(), CliError> {
    check::run(&args.path, verbose, !quiet)
}
