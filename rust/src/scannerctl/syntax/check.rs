// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::{Path, PathBuf};

use scannerlib::nasl::syntax::load_non_utf8_path;
use scannerlib::nasl::syntax::{parse, Statement, SyntaxError};
use walkdir::WalkDir;

use crate::{CliError, CliErrorKind};

fn read<P: AsRef<Path>>(path: P) -> Result<Vec<Result<Statement, SyntaxError>>, CliErrorKind> {
    let code = load_non_utf8_path(path.as_ref())?;
    Ok(parse(&code).collect())
}

fn print_results(path: &Path, verbose: bool) -> Result<usize, CliError> {
    let mut errors = 0;

    let print_error = |err: &SyntaxError| {
        if let Some(token) = err.as_token() {
            eprintln!(
                "{}:{}:{}: {}",
                path.to_string_lossy(),
                token.line(),
                token.column(),
                err.kind
            )
        } else {
            eprintln!("{}:{}", path.to_string_lossy(), err)
        }
    };
    let print_stmt = |stmt: Statement| {
        println!(
            "{}:{}:{}: {}",
            path.to_string_lossy(),
            stmt.as_token().line(),
            stmt.as_token().column(),
            stmt
        )
    };

    let results = read(path).map_err(|kind| CliError {
        kind,
        filename: path.to_string_lossy().to_string(),
    })?;
    for r in results {
        match r {
            Ok(stmt) if verbose => print_stmt(stmt),
            Ok(_) => {}
            Err(err) => {
                // when we run in interactive mode we should print a new line to
                // not interfere with the count display.
                if errors == 0 {
                    eprintln!()
                }
                errors += 1;
                print_error(&err)
            }
        }
    }
    Ok(errors)
}

pub fn run(path: &PathBuf, verbose: bool, no_progress: bool) -> Result<(), CliError> {
    let mut parsed: usize = 0;
    let mut skipped: usize = 0;
    let mut errors: usize = 0;
    println!("verifying NASL syntax in {path:?}.");
    if path.as_path().is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if !no_progress {
                print!("\rparsing {parsed}th file");
            }
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
                errors += print_results(entry.path(), verbose)?;
                parsed += 1;
            }
        }
        println!();
    } else {
        errors += print_results(path.as_path(), verbose)?;
        parsed += 1;
    }
    println!("skipped: {skipped} files; parsed: {parsed} files; errors: {errors}");
    if errors > 0 {
        std::process::exit(errors as i32);
    }
    Ok(())
}
