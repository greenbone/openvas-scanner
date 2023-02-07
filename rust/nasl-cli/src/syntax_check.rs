use std::{fs, io, path::{Path, PathBuf}};

use nasl_interpreter::FSPluginLoader;
use nasl_syntax::{SyntaxError, Statement};
use walkdir::WalkDir;

use crate::CliError;

fn read_errors<P: AsRef<Path>>(path: P) -> Result<Vec<SyntaxError>, CliError> {
    let code = FSPluginLoader::load_non_utf8_path(path.as_ref())?;
    Ok(nasl_syntax::parse(&code)
        .filter_map(|r| match r {
            Ok(_) => None,
            Err(err) => Some(err),
        })
        .collect())
}

fn read<P: AsRef<Path>>(path: P) -> Result<Vec<Result<Statement, SyntaxError>>, CliError> {
    let code = FSPluginLoader::load_non_utf8_path(path.as_ref())?;
    Ok(nasl_syntax::parse(&code).collect())
}

fn print_results(path: &Path, verbose: bool) -> Result<usize, CliError> {
    let mut errors = 0;

    if verbose {
        println!("# {path:?}");
        let results = read(path)?;
        for r in results {
            match r {
                Ok(stmt) => println!("{stmt:?}"),
                Err(err) => eprintln!("{err}"),
            }
        }
    } else {
        let err = read_errors(path)?;
        if !err.is_empty() {
            eprintln!("# Error in {path:?}");
        }
        errors += err.len();
        err.iter().for_each(|r| eprintln!("{r}"));
    }
    Ok(errors)
}

pub fn run(path: &PathBuf, verbose: bool) -> Result<(), CliError> {
    let mut parsed: usize = 0;
    let mut skipped: usize = 0;
    let mut errors: usize = 0;
    println!("verifiying NASL syntax in {path:?}.");
    if path.as_path().is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            print!("\rparsing {parsed}th file");
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
    Ok(())
}

