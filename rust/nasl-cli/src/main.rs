use std::{
    fs, io,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use nasl_syntax::{Statement, SyntaxError};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Subcommand to print the raw statements of a file.
    ///
    /// It is mostly for debug purposes and verification if the nasl-syntax-parser is working as expected.
    Syntax {
        /// The path for the file or dir to parse
        #[arg(short, long)]
        path: PathBuf,
        /// prints the parsed statements
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    },
}

fn load_file<P: AsRef<Path>>(path: P) -> Result<String, io::Error> {
    // unfortunately NASL is not UTF-8 so we need to map it manually
    fs::read(path).map(|bs| bs.iter().map(|&b| b as char).collect())
}

fn read_errors<P: AsRef<Path>>(path: P) -> Result<Vec<SyntaxError>, SyntaxError> {
    let code = load_file(path)?;
    Ok(nasl_syntax::parse(&code)
        .filter_map(|r| match r {
            Ok(_) => None,
            Err(err) => Some(err),
        })
        .collect())
}

fn read<P: AsRef<Path>>(path: P) -> Result<Vec<Result<Statement, SyntaxError>>, SyntaxError> {
    let code = load_file(path)?;
    Ok(nasl_syntax::parse(&code).collect())
}

fn print_results(path: &Path, verbose: bool) -> usize {
    let mut errors = 0;

    if verbose {
        println!("# {:?}", path);
        let results = read(path).unwrap();
        for r in results {
            match r {
                Ok(stmt) => println!("{:?}", stmt),
                Err(err) => eprintln!("{}", err),
            }
        }
    } else {
        let err = read_errors(&path).unwrap();
        if !err.is_empty() {
            eprintln!("# Error in {:?}", path);
        }
        errors += err.len();
        err.iter().for_each(|r| eprintln!("{}", r));
    }
    errors
}

fn syntax_check(path: PathBuf, verbose: bool) {
    let mut parsed: usize = 0;
    let mut skipped: usize = 0;
    let mut errors: usize = 0;
    println!("verifiying NASL syntax in {:?}.", path);
    if path.as_path().is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            print!("\rparsing {}th file", parsed);
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
                errors += print_results(entry.path(), verbose);
                parsed += 1;
            }
        }
        println!();
    } else {
        errors += print_results(path.as_path(), verbose);
        parsed += 1;
    }
    println!(
        "skipped: {} files; parsed: {} files; errors: {}",
        skipped, parsed, errors
    );
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Syntax { path, verbose } => syntax_check(path, verbose),
    }
}
