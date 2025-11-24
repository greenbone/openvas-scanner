// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::Path;

use scannerlib::nasl::Code;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::syntax::grammar::Statement;
use walkdir::WalkDir;

use crate::CliError;

fn print_results(path: &Path, verbose: bool) -> Result<usize, CliError> {
    let mut num_errors = 0;

    let print_stmt = |stmt: &Statement| {
        println!("{}: {}", path.to_string_lossy(), stmt);
    };
    let loader = Loader::from_feed_path(".");
    let results = Code::load(&loader, path)?.parse();
    num_errors += results.num_errors();
    if let Ok(stmts) = results.emit_errors()
        && verbose
    {
        for stmt in stmts.stmts().iter() {
            print_stmt(stmt);
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
