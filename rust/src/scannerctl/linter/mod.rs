mod cli;
mod ctx;
mod lints;
#[cfg(test)]
pub(crate) mod tests;

use std::{collections::HashSet, path::PathBuf};

pub use cli::LinterArgs;
use cli::get_files_and_loader;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use ctx::{Cache, CachedFile, LintCtx};
use lints::{Lint, LintMsg, all_lints};
use scannerlib::nasl::{
    Code, Loader, SourceFile,
    error::{IntoDiagnostic, emit_errors},
    syntax::{
        LoadError, ParseError,
        grammar::{Ast, Include},
    },
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
            let msgs = self.lint_file(&file.to_string_lossy())?;
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

    fn lint_file(&mut self, rel_path: &str) -> Result<LintMsgs, LoadError> {
        self.cache.clear_files();
        let code = self.load(rel_path)?;
        let file = code.file();
        let ast = match self.parse_file(code) {
            Ok(ast) => ast,
            Err(msgs) => return Ok(LintMsgs { file, msgs }),
        };
        let msgs = if self.only_syntax {
            vec![]
        } else {
            self.cache.insert(rel_path, CachedFile::new(&ast));
            let mut loaded = HashSet::from([rel_path.to_owned()]);
            if let Err(msgs) = self.load_includes(&ast, &file, &mut loaded) {
                return Ok(msgs);
            }

            let ctx = LintCtx::new(&ast, &mut self.cache);
            self.lints.iter().flat_map(|lint| lint.lint(&ctx)).collect()
        };
        Ok(LintMsgs { file, msgs })
    }

    fn load_includes(
        &mut self,
        ast: &Ast,
        file: &SourceFile,
        loaded: &mut HashSet<String>,
    ) -> Result<(), LintMsgs> {
        for include in ast.iter_includes() {
            if !loaded.insert(include.path.clone()) {
                continue;
            }

            let code = self.load(&include.path).map_err(|_| LintMsgs {
                file: file.clone(),
                msgs: vec![make_load_error_msg(include)],
            })?;
            let include_file = code.file();
            let include_ast = self.parse_file(code).map_err(|msgs| LintMsgs {
                file: include_file.clone(),
                msgs,
            })?;

            self.cache
                .insert(&include.path, CachedFile::new(&include_ast));
            self.load_includes(&include_ast, &include_file, loaded)?;
        }
        Ok(())
    }

    fn parse_file(&self, code: Code) -> Result<Ast, Vec<LintMsg>> {
        let parsed = code.parse();
        let result = parsed.result();
        result.map_err(|e| {
            e.into_iter()
                .map(ParseError::into_diagnostic)
                .map(|diagnostic| diagnostic.into())
                .collect()
        })
    }

    fn load(&mut self, rel_path: &str) -> Result<Code, LoadError> {
        Code::load(&self.loader, rel_path)
    }

    fn handle_msgs(&mut self, msgs: LintMsgs) {
        self.stats.errors += msgs.msgs.len();
        if !self.quiet {
            emit_errors(&msgs.file, msgs.msgs.into_iter());
        }
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
