mod cli;
mod ctx;
mod lints;
#[cfg(test)]
pub(crate) mod tests;

use std::path::{Path, PathBuf};

pub use cli::LinterArgs;
use cli::get_files_and_loader;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use ctx::{Cache, LintCtx};
use lints::{Lint, LintMsg, all_lints};
use scannerlib::nasl::{
    Code, Loader, SourceFile,
    error::{IntoDiagnostic, emit_errors},
    syntax::{LoadError, ParseError, grammar::Include},
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

struct LintMsgs {
    file: SourceFile,
    msgs: Vec<LintMsg>,
}

impl Linter {
    fn run(&mut self, files: &[PathBuf]) -> Result<(), CliError> {
        for file in files.iter() {
            if self.verbose {
                println!("Linting file: {:?}", file);
            }
            self.stats.checked += 1;
            let msgs = self.lint_file(file)?;
            self.handle_msgs(msgs);
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

    fn lint_file(&mut self, rel_path: &Path) -> Result<LintMsgs, LoadError> {
        let parsed = self
            .cache
            .parse(rel_path, || Code::load(&self.loader, rel_path))?;
        let file = parsed.file.clone();
        let ast = match &parsed.ast {
            Ok(ast) => ast,
            Err(errors) => return Ok(parse_error_msgs(file, errors)),
        };
        let msgs = if self.only_syntax {
            vec![]
        } else {
            let includes: Vec<_> = ast.iter_includes().cloned().collect();
            let mut include_paths = vec![];
            for include in includes {
                // TODO
                let loaded = match include.path.load(&self.loader, rel_path) {
                    Ok(loaded) => loaded,
                    Err(_) => {
                        // TODO report multiple errors here if multiple files
                        // cannot be found.
                        return Ok(LintMsgs {
                            file,
                            msgs: vec![make_load_error_msg(&include)],
                        });
                    }
                };
                let include_path = loaded.path().to_owned();
                let included = self.cache.parse(&include_path, || Ok(Code::from(loaded)))?;
                if let Err(errors) = &included.ast {
                    return Ok(parse_error_msgs(included.file.clone(), errors));
                }
                include_paths.push(include_path);
            }

            let ast = self.cache.get(rel_path).ast.as_ref().unwrap();
            let includes = include_paths
                .iter()
                .map(|path| self.cache.get(path).ast.as_ref().unwrap())
                .collect();
            let ctx = LintCtx::new(ast, includes);
            self.lints.iter().flat_map(|lint| lint.lint(&ctx)).collect()
        };
        Ok(LintMsgs { file, msgs })
    }

    fn handle_msgs(&mut self, msgs: LintMsgs) {
        self.stats.errors += msgs.msgs.len();
        if !self.quiet {
            emit_errors(&msgs.file, msgs.msgs.into_iter());
        }
    }
}

fn parse_error_msgs(file: SourceFile, errors: &[ParseError]) -> LintMsgs {
    LintMsgs {
        file,
        msgs: errors
            .iter()
            .cloned()
            .map(ParseError::into_diagnostic)
            .map(Into::into)
            .collect(),
    }
}

fn make_load_error_msg(include: &Include) -> LintMsg {
    let msg = format!("Could not find file '{:?}'", include.path);
    Diagnostic::error()
        .with_message(&msg)
        .with_labels(vec![Label::primary((), include.span).with_message(&msg)])
        .into()
}

pub(crate) async fn run(
    args: LinterArgs,
    verbose: bool,
    quiet: bool,
    only_syntax: bool,
) -> Result<(), CliError> {
    let (loader, files) = get_files_and_loader(&args)?;
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
