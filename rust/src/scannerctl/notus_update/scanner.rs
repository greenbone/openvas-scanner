// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    io,
    path::{Path, PathBuf},
};

use scannerlib::notus::{FSProductLoader, Notus};

use crate::{CliError, utils::ArgOrStdin};

#[derive(Debug)]
struct PackageList(Vec<String>);

impl PackageList {
    fn new(s: &str) -> Self {
        Self(s.split(',').map(String::from).collect::<Vec<_>>())
    }
}

/// Compare package versions against known vulnerabilities
/// using notus products.
#[derive(clap::Parser)]
pub struct NotusUpdateArgs {
    /// Path to the product feed.
    #[clap(long)]
    path: PathBuf,
    /// A comma separated list of packages.
    /// If '-' is given, the list will be read from stdin instead.
    #[clap(long)]
    pkg_list: ArgOrStdin<String>,
    /// The OS to use.
    os: String,
}

pub async fn run(args: NotusUpdateArgs) -> Result<(), CliError> {
    let pkg_list = match args.pkg_list {
        ArgOrStdin::Stdin => io::read_to_string(io::stdin())?,
        ArgOrStdin::Arg(pkg_list) => pkg_list,
    };
    let pkg_list = PackageList::new(&pkg_list);
    execute(pkg_list, &args.os, args.path)
}

fn execute<T>(packages: PackageList, os: &str, products_path: T) -> Result<(), CliError>
where
    T: AsRef<Path>,
{
    let loader = FSProductLoader::new(products_path)?;
    let mut notus = Notus::new(loader, false);
    tracing::debug!(?packages, "going to scan");
    serde_json::to_writer_pretty(io::stdout(), &notus.scan(os, &packages.0)?)?;
    Ok(())
}
