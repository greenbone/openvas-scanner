mod cli;
mod ctx;
mod lints;

use std::path::PathBuf;

pub use cli::LinterArgs;
use cli::get_files_and_loader;
use ctx::{Cache, LintCtx};
use lints::{Lint, LintMsg, all_lints};
use scannerlib::nasl::{
    Code, Loader,
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
    verbose: bool,
    quiet: bool,
    only_syntax: bool,

    loader: Loader,

    stats: Statistics,
    lints: Vec<Box<dyn Lint>>,

    cache: Cache,
}

impl Linter {
    fn run(&mut self, files: &[PathBuf]) -> Result<(), CliError> {
        for file in files.iter() {
            if self.verbose {
                println!("Linting file: {:?}", file);
            }
            self.stats.checked += 1;
            let code = Code::load(&self.loader, file)?;
            let parsed = code.parse();
            let file = parsed.file().clone();
            let msgs = self.lint_file(file.name().into(), parsed.result());
            self.stats.errors += msgs.len();
            if !self.quiet {
                emit_errors(&file, msgs.into_iter());
            }
        }
        if self.verbose {
            println!(
                "Checked: {}, Errors: {}",
                self.stats.checked, self.stats.errors
            );
        }
        if self.stats.errors > 0 {
            Err(CliErrorKind::LinterError.into())
        } else {
            Ok(())
        }
    }

    fn lint_file(
        &mut self,
        file_path: std::path::PathBuf,
        result: Result<Ast, Vec<ParseError>>,
    ) -> Vec<LintMsg> {
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
            self.cache
                .add_file_functions(file_path.to_string_lossy().to_string(), &ast);

            let ctx = LintCtx::new(&ast, &mut self.cache);
            self.lints.iter().flat_map(|lint| lint.lint(&ctx)).collect()
        }
    }
}

pub(crate) async fn run(
    args: LinterArgs,
    verbose: bool,
    quiet: bool,
    only_syntax: bool,
) -> Result<(), CliError> {
    let (loader, files) = get_files_and_loader(&args.path)?;
    let lints = all_lints();
    let mut linter = Linter {
        verbose,
        quiet,
        only_syntax,
        lints,
        stats: Statistics::default(),
        cache: Cache::default(),

        loader,
    };
    linter.run(&files)?;
    Ok(())
}
