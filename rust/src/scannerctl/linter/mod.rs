mod cli;
mod ctx;
mod lints;
#[cfg(test)]
pub(crate) mod tests;

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

pub use cli::LinterArgs;
use cli::get_files_and_loader;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use ctx::{Cache, CachedFile, LintCtx};
use lints::{Lint, LintMsg, LintScope, all_lints};
use scannerlib::nasl::{
    Code, Loader, SourceFile,
    error::{IntoDiagnostic, emit_errors},
    syntax::{ParseError, grammar::Include},
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
        let quiet = self.quiet;
        self.run_with_emit(files, |msgs| {
            if !quiet {
                emit_errors(&msgs.file, msgs.msgs.into_iter());
            }
        })
    }

    fn run_with_emit(
        &mut self,
        files: &[PathBuf],
        mut emit: impl FnMut(LintMsgs),
    ) -> Result<(), CliError> {
        self.populate_cache(files, &mut emit);
        if self.stats.errors == 0 && !self.only_syntax {
            for path in self.cache.paths() {
                let cached = self.cache.get(&path);
                let ctx = LintCtx::new(&cached.ast, vec![]);
                let msgs = LintMsgs {
                    file: cached.file.clone(),
                    msgs: self
                        .lints
                        .iter()
                        .filter(|lint| lint.scope() == LintScope::File)
                        .flat_map(|lint| lint.lint(&ctx))
                        .collect(),
                };
                self.handle_msgs(msgs, &mut emit);
            }
            for file in files {
                if self.verbose {
                    println!("Linting file: {:?}", file);
                }
                for msgs in self.lint_file(file) {
                    self.handle_msgs(msgs, &mut emit);
                }
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

    fn populate_cache(&mut self, files: &[PathBuf], emit: &mut impl FnMut(LintMsgs)) {
        let mut pending: Vec<_> = files
            .iter()
            .rev()
            .map(|path| (path.clone(), None))
            .collect();
        let mut visited = HashSet::new();
        while let Some((path, code)) = pending.pop() {
            if !visited.insert(path.clone()) {
                continue;
            }
            self.stats.checked += 1;
            let code = match code
                .map(Ok)
                .unwrap_or_else(|| Code::load(&self.loader, &path))
            {
                Ok(code) => code,
                Err(error) => {
                    self.handle_msgs(
                        LintMsgs {
                            file: SourceFile::new(
                                path.to_string_lossy().into_owned(),
                                String::new(),
                            ),
                            msgs: vec![Diagnostic::error().with_message(error.to_string()).into()],
                        },
                        emit,
                    );
                    continue;
                }
            };
            let parsed = code.parse();
            let file = parsed.file().clone();
            let ast = match parsed.result() {
                Ok(ast) => ast,
                Err(errors) => {
                    self.handle_msgs(parse_error_msgs(file, &errors), emit);
                    continue;
                }
            };
            let mut includes = vec![];
            let mut loaded_includes = vec![];
            for include in ast.iter_includes() {
                match include.path.load(&self.loader, &path) {
                    Ok(loaded) => {
                        let include_path = loaded.path().to_owned();
                        includes.push(include_path.clone());
                        loaded_includes.push((include_path, Some(Code::from(loaded))));
                    }
                    Err(_) => self.handle_msgs(
                        LintMsgs {
                            file: file.clone(),
                            msgs: vec![make_load_error_msg(include)],
                        },
                        emit,
                    ),
                }
            }
            self.cache.insert(
                path,
                CachedFile {
                    file,
                    ast,
                    includes,
                },
            );
            pending.extend(loaded_includes.into_iter().rev());
        }
    }

    fn lint_file(&self, path: &Path) -> Vec<LintMsgs> {
        let root = self.cache.get(path);
        let mut pending: Vec<_> = root.includes.iter().rev().collect();
        let mut visited = HashSet::from([path]);
        let mut files = vec![root];
        while let Some(path) = pending.pop() {
            if !visited.insert(path.as_path()) {
                continue;
            }
            let cached = self.cache.get(path);
            files.push(cached);
            pending.extend(cached.includes.iter().rev());
        }
        files
            .iter()
            .enumerate()
            .map(|(index, file)| {
                let includes = files
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .map(|(_, file)| &file.ast)
                    .collect();
                let ctx = LintCtx::new(&file.ast, includes);
                LintMsgs {
                    file: file.file.clone(),
                    msgs: self
                        .lints
                        .iter()
                        .filter(|lint| lint.scope() == LintScope::Root)
                        .flat_map(|lint| lint.lint(&ctx))
                        .collect(),
                }
            })
            .collect()
    }

    fn handle_msgs(&mut self, msgs: LintMsgs, emit: &mut impl FnMut(LintMsgs)) {
        self.stats.errors += msgs.msgs.len();
        emit(msgs);
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
