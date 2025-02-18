// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::Path;

use scannerlib::nasl::syntax::load_non_utf8_path;
use scannerlib::nasl::syntax::{parse, Statement, SyntaxError};
use scannerlib::nasl::WithErrorInfo;
use walkdir::WalkDir;

use crate::{CliError, CliErrorKind, Filename};

fn read<P: AsRef<Path>>(path: P) -> Result<Vec<Result<Statement, SyntaxError>>, CliErrorKind> {
    let code = load_non_utf8_path(path.as_ref())?;
    Ok(parse(&code).collect())
}

fn print_results(path: &Path, verbose: bool) -> Result<usize, CliError> {
    let mut num_errors = 0;

    if verbose {
        println!("# {path:?}");
    }
    let results = read(path).map_err(|e| e.with(Filename(path)))?;
    for r in results {
        match r {
            Ok(stmt) => {
                if verbose {
                    println!("{stmt:?}")
                }
            }
            Err(err) => {
                num_errors += 1;
                eprintln!("{err}")
            }
        }
    }
    Ok(num_errors)
}

pub fn run(path: &Path, verbose: bool, quiet: bool) -> Result<(), CliError> {
    let mut parsed: usize = 0;
    let mut skipped: usize = 0;
    let mut errors: usize = 0;
    println!("Verifying NASL syntax in {path:?}.");
    if path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if !quiet {
                print!("\rparsing file #{parsed}");
            }
            if let Some("nasl") | Some("inc") =
                entry.path().extension().and_then(|ext| ext.to_str())
            {
                errors += print_results(entry.path(), verbose)?;
                parsed += 1;
            } else {
                skipped += 1;
            }
        }
        println!();
    } else {
        errors += print_results(path, verbose)?;
        parsed += 1;
    }
    println!("skipped: {skipped} files; parsed: {parsed} files; errors: {errors}");
    if errors > 0 {
        std::process::exit(errors as i32);
    }
    Ok(())
}
