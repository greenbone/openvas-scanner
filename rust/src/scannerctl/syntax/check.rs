// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::{Path, PathBuf};

use scannerlib::nasl::{
    Code, Loader,
    syntax::{Declaration, LoadError, load_non_utf8_path},
};
use walkdir::WalkDir;

use crate::CliError;

struct NonUtf8Loader;

impl Loader for NonUtf8Loader {
    fn load(&self, key: &str) -> Result<String, LoadError> {
        load_non_utf8_path(key)
    }

    fn root_path(&self) -> Result<String, LoadError> {
        Ok(".".to_owned())
    }
}

fn print_results(path: &Path, verbose: bool) -> Result<usize, CliError> {
    let mut errors = 0;

    let print_decl = |decl: &Declaration| {
        println!("{}: {}", path.to_string_lossy(), decl);
    };

    let results = Code::load(&NonUtf8Loader, path)?.parse();
    errors += results.num_errors();
    match results.emit_errors() {
        Some(decls) => {
            if verbose {
                for decl in decls.decls().iter() {
                    print_decl(decl);
                }
            }
        }
        None => {}
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
