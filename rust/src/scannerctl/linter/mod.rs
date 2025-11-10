mod cli;
mod lints;

use std::path::PathBuf;

pub use cli::LinterArgs;
use cli::get_files;
use lints::{Lint, LintMsg, all_lints};
use scannerlib::nasl::{
    Code,
    error::{IntoDiagnostic, emit_errors},
    syntax::{ParseError, grammar::Ast},
};

use crate::error::{CliError, CliErrorKind};

#[derive(Default)]
struct Statistics {
    checked: usize,
    errors: usize,
}

struct Linter {
    files: Vec<PathBuf>,
    verbose: bool,
    quiet: bool,
    only_syntax: bool,

    stats: Statistics,
    lints: Vec<Box<dyn Lint>>,
}

impl Linter {
    fn run(&mut self) -> Result<(), CliError> {
        for file in self.files.iter() {
            if self.verbose {
                println!("Linting file: {:?}", file);
            }
            self.stats.checked += 1;
            let code = Code::load(todo!(), file)?;
            let parsed = code.parse();
            let file = parsed.file().clone();
            let msgs = self.lint_file(parsed.result());
            self.stats.errors += msgs.len();
            if !self.quiet {
                emit_errors(&file, msgs.into_iter());
            }
        }
        if self.stats.errors > 0 {
            Err(CliErrorKind::LinterError.into())
        } else {
            Ok(())
        }
    }

    fn lint_file(&self, result: Result<Ast, Vec<ParseError>>) -> Vec<LintMsg> {
        let ast = match result {
            Ok(ast) => ast,
            Err(e) => {
                return e
                    .into_iter()
                    .map(ParseError::into_diagnostic)
                    .map(|diagnostic| diagnostic.into())
                    .collect();
            }
        };
        if self.only_syntax {
            vec![]
        } else {
            self.lints.iter().flat_map(|lint| lint.lint(&ast)).collect()
        }
    }
}

pub(crate) async fn run(
    args: LinterArgs,
    verbose: bool,
    quiet: bool,
    only_syntax: bool,
) -> Result<(), CliError> {
    let files = get_files(&args.path)?;
    let lints = all_lints();
    let mut linter = Linter {
        files,
        verbose,
        quiet,
        only_syntax,
        lints,
        stats: Statistics::default(),
    };
    linter.run()?;
    Ok(())
}
