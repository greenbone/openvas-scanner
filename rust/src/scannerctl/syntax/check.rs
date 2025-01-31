// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::{Path, PathBuf};

use scannerlib::nasl::syntax::load_non_utf8_path;
use scannerlib::nasl::syntax::{parse, Statement, SyntaxError};
use scannerlib::nasl::WithErrorInfo;
use tracing::{debug, error, info};
use walkdir::WalkDir;

use crate::{CliError, CliErrorKind, Filename};

fn read<P: AsRef<Path>>(path: P) -> Result<Vec<Result<Statement, SyntaxError>>, CliErrorKind> {
    let code = load_non_utf8_path(path.as_ref())?;
    Ok(parse(&code).collect())
}

fn print_results(path: &Path) -> Result<usize, CliError> {
    let mut num_errors = 0;

    println!("# {path:?}");
    let results = read(path).map_err(|e| e.with(Filename(path)))?;
    for r in results {
        match r {
            Ok(stmt) => debug!("{stmt:?}"),
            Err(err) => {
                num_errors += 1;
                error!("{err}")
            }
        }
    }
    Ok(num_errors)
}

pub fn run(path: &PathBuf) -> Result<(), CliError> {
    let mut parsed: usize = 0;
    let mut skipped: usize = 0;
    let mut errors: usize = 0;
    info!("Verifying NASL syntax in {path:?}.");
    if path.as_path().is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            debug!("\rparsing {parsed}th file");
            let ext = {
                if let Some(ext) = entry.path().extension() {
                    ext.to_str().unwrap().to_owned()
                } else {
                    "".to_owned()
                }
            };
            if !matches!(ext.as_str(), "nasl" | "inc") {
                skipped += 1;
            } else {
                errors += print_results(entry.path())?;
                parsed += 1;
            }
        }
        println!();
    } else {
        errors += print_results(path.as_path())?;
        parsed += 1;
    }
    println!("skipped: {skipped} files; parsed: {parsed} files; errors: {errors}");
    if errors > 0 {
        std::process::exit(errors as i32);
    }
    Ok(())
}
