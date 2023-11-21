// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fs::File, io::Read, path::PathBuf};

use clap::{arg, value_parser, ArgAction, Command};
use notus::{loader::fs::FSAdvisoryLoader, notus::Notus};

fn main() {
    let matches = Command::new("nasl-cli")
        .version("1.0")
        .about("Is a CLI tool around Notus.")
        .arg(
            arg!(-p --path <FILE> "Path to the notus advisories.")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-s --os <STRING> "To the packages corresponding operating system").required(true))
        .arg(
            arg!(-f --"pkg-file" <FILE> "Path to the notus packages to check for vulnerabilities, the file should contain a comma separated list of packages")
                .required_unless_present("pkg-list")
                .conflicts_with("pkg-list")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-l --"pkg-list" <STRING> "A comma separated list of packages to check for vulnerabilities")
                .required_unless_present("pkg-file"),
        )
        .arg(
            arg!(-n --pretty "Enables pretty printing for the result").action(ArgAction::SetTrue)
        )
        .get_matches();

    let advisory_path = matches.get_one::<PathBuf>("path").unwrap();
    let loader = match FSAdvisoryLoader::new(advisory_path) {
        Ok(loader) => loader,
        Err(err) => {
            eprintln!("{err}");
            return;
        }
    };

    let mut buf;
    match matches.get_one::<PathBuf>("pkg-file") {
        Some(path) => {
            buf = String::new();
            File::open(path).unwrap().read_to_string(&mut buf).unwrap();
        }
        None => {
            buf = matches.get_one::<String>("pkg-list").unwrap().to_string();
        }
    };
    let packages = buf.split(',').map(str::to_string).collect::<Vec<String>>();

    let os = matches.get_one::<String>("os").unwrap();

    let mut notus = Notus::new(loader);
    match notus.scan(os, &packages) {
        Ok(results) => {
            let json = match matches.contains_id("pretty") {
                true => serde_json::to_string_pretty(&results).unwrap(),
                false => serde_json::to_string(&results).unwrap(),
            };

            println!("{json}");
        }
        Err(err) => eprintln!("{err}"),
    }
}
