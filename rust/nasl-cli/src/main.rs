use std::{fs, io, ops::Range, path::PathBuf};

use clap::{Parser, Subcommand};
use nasl_syntax::{Statement, SyntaxError};

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
        /// If given path should it be read recursively
        #[arg(short, long, default_value_t = false)]
        recursive: bool,
    },
}

fn get_range(err: &SyntaxError) -> Option<Range<usize>> {
    if let Some(token) = err.token {
        Some(token.range())
    } else if let Some(Statement::Primitive(token)) = err.statement {
        Some(token.range())
    } else {
        None
    }
}

fn report_error(code: &str, err: SyntaxError) {
    if let Some(range) = get_range(&err) {
        let character = code[range.clone()].to_owned();
        let line = code[Range{ start: 0, end: range.end}].as_bytes().iter().filter(|&&c| c == b'\n').count();
        eprintln!("error at line {}: {}", line, character)
    }
    eprintln!("Unknown error: {:?}", err);
}

fn read_file(path: PathBuf) -> Result<(), io::Error> {
    // unfortunately NASL is not UTF-8 so we need to map it manually
    let code: String = fs::read(path).map(|bs| bs.iter().map(|&b| b as char).collect())?;
    nasl_syntax::parse(&code).for_each(|x| match x {
        Ok(x) => println!("{:?}", x),
        Err(x) => report_error(&code, x),
    });
    Ok(())
}

fn synatx(path: PathBuf, _recursive: bool) {
    if path.as_path().is_dir() {
        todo!("Reading a path is not yet supported.")
    } else {
        read_file(path).unwrap()
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Syntax { path, recursive } => synatx(path, recursive),
    }

    //       let code: String = fs::read(path).map(|bs| bs.iter().map(|&b| b as char).collect())?;
}
