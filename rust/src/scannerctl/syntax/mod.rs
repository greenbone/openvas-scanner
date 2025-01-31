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
    /// Print more details while running
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Print only error output.
    #[arg(short, long)]
    pub quiet: bool,
}

pub async fn run(args: SyntaxArgs) -> Result<(), CliError> {
    check::run(&args.path, args.verbose > 0, args.quiet)
}
