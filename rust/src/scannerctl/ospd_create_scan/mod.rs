// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::{Display, Formatter};
use std::{io::BufReader, path::PathBuf, sync::Arc};

use clap::{arg, value_parser, Arg, ArgAction, Command};
use scannerlib::models::{AliveTestMethods, Parameter, Port, Protocol, Scan, VT};
use scannerlib::storage::{ContextKey, DefaultDispatcher, Retriever, StorageError};
use serde::{Deserialize, Serialize};

use crate::{get_path_from_openvas, read_openvas_config, CliError, CliErrorKind};
use scannerlib::storage::item::{NVTField, NVTKey};
use scannerlib::storage::Field;
use scannerlib::storage::Retrieve;
use std::collections::{HashMap, HashSet};
use std::io::BufRead;
mod create;

pub fn extend_args(cmd: Command) -> Command {
    cmd.subcommand(crate::add_verbose(
        Command::new("ospd")
            .about("Transforms a ospd-start-scan xml to a scan json for openvasd. ")
            .arg(
                arg!(-p --path <FILE> "Path to the feed.")
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("ospd_xml")
                    .required(false)
                    .action(ArgAction::Append),
            )
            .arg(
                arg!(-i --input "Parses ospd command from stdin.")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                arg!(-b --back "Serializes start scan command and pretty prints it back to stdout.")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
    ))
}

pub async fn run(root: &clap::ArgMatches) -> Option<Result<(), CliError>> {
    let (args, _) = crate::get_args_set_logging(root, "ospd")?;

    let feed = args.get_one::<PathBuf>("path").cloned();
    let config = args.get_one::<String>("ospd_xml");
    let stdin = args.get_one::<bool>("input").cloned().unwrap_or_default();
    if config.is_none() && !stdin {
        return Some(Err(CliError {
            filename: Default::default(),
            kind: CliErrorKind::MissingArguments(vec![
                "-i --input".to_string(),
                "ospd_xml".to_string(),
            ]),
        }));
    }
    let bufreader = {
        if stdin {
            BufReader::new(std::io::stdin())
        } else {
            todo!()
        }
    };
    let sc: create::StartScan = match quick_xml::de::from_reader(bufreader) {
        Ok(x) => x,
        Err(x) => {
            return Some(Err(CliError {
                filename: Default::default(),
                kind: CliErrorKind::Corrupt(format!("Cannot parse XML: {x}")),
            }))
        }
    };
    let print_back = args
        .get_one::<bool>("back")
        .cloned()
        .unwrap_or_default();
    if print_back {
        println!("{sc}");
    } else {
        todo!()
    }
    Some(Ok(()))
}

#[cfg(test)]
mod tests {
    use scannerlib::storage::{item::NVTField, ContextKey, DefaultDispatcher, Field, Storage};

    use super::*;
}
