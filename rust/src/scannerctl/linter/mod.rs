mod cli;
mod ctx;
mod lints;
#[cfg(test)]
pub(crate) mod tests;

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

pub use cli::LinterArgs;
use cli::get_files_and_loader;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use ctx::{Cache, CachedFile, LintCtx};
use lints::{Lint, LintMsg, LintMsgKey, all_lints};
use scannerlib::nasl::{
    Code, Loader, SourceFile,
    error::{IntoDiagnostic, emit_errors},
    syntax::{
        LoadError, ParseError,
        grammar::{Ast, Include},
    },
};

use crate::error::{CliError, CliErrorKind};

type ParsedFile = Result<Arc<CachedFile>, Vec<LintMsg>>;

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
    parsed_includes: HashMap<String, ParsedFile>,
    lint_msgs: HashSet<LintMsgKey>,
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

    fn lint_file(&mut self, rel_path: &str) -> Result<Vec<LintMsg>, LoadError> {
        self.cache.clear_files();
        let root = match self.get_or_parse_root(rel_path)? {
            Ok(root) => root,
            Err(msgs) => return Ok(msgs),
        };
        self.cache.insert(rel_path, root.clone());
        let mut loaded = HashSet::from([rel_path.to_owned()]);
        if let Err(msgs) = self.load_includes(root.ast(), root.file(), &mut loaded) {
            return Ok(msgs);
        }

        let msgs = if self.only_syntax {
            vec![]
        } else {
            let ctx = LintCtx::new(root.ast(), root.file(), &mut self.cache);
            self.lints.iter().flat_map(|lint| lint.lint(&ctx)).collect()
        };
        Ok(msgs)
    }

    fn load_includes(
        &mut self,
        ast: &Ast,
        file: &SourceFile,
        loaded: &mut HashSet<String>,
    ) -> Result<(), Vec<LintMsg>> {
        for include in ast.iter_includes() {
            if !loaded.insert(include.path.clone()) {
                continue;
            }

            let included = self
                .get_or_parse_include(&include.path)
                .map_err(|_| vec![make_load_error_msg(file.clone(), include)])??;

            self.cache.insert(&include.path, included.clone());
            self.load_includes(included.ast(), included.file(), loaded)?;
        }
        Ok(())
    }

    fn get_or_parse_root(&self, rel_path: &str) -> Result<ParsedFile, LoadError> {
        if let Some(parsed) = self.parsed_includes.get(rel_path) {
            return Ok(parsed.clone());
        }
        self.parse_path(rel_path)
    }

    fn get_or_parse_include(&mut self, rel_path: &str) -> Result<ParsedFile, LoadError> {
        if let Some(parsed) = self.parsed_includes.get(rel_path) {
            return Ok(parsed.clone());
        }

        let parsed = self.parse_path(rel_path)?;
        self.parsed_includes
            .insert(rel_path.to_owned(), parsed.clone());
        Ok(parsed)
    }

    fn parse_path(&self, rel_path: &str) -> Result<ParsedFile, LoadError> {
        let code = self.load(rel_path)?;
        let file = code.file();
        Ok(self
            .parse_file(code)
            .map(|ast| Arc::new(CachedFile::new(file, &ast))))
    }

    fn parse_file(&self, code: Code) -> Result<Ast, Vec<LintMsg>> {
        let file = code.file();
        let parsed = code.parse();
        let result = parsed.result();
        result.map_err(|e| {
            e.into_iter()
                .map(|error| {
                    let span = error.span;
                    let diagnostic = ParseError::into_diagnostic(error);
                    LintMsg::new("syntax", file.clone(), span, diagnostic)
                })
                .collect()
        })
    }

    fn load(&self, rel_path: &str) -> Result<Code, LoadError> {
        Code::load(&self.loader, rel_path)
    }

    fn handle_msgs(&mut self, msgs: Vec<LintMsg>) {
        let msgs = self.deduplicate(msgs);
        self.stats.errors += msgs.len();
        if !self.quiet {
            for msg in msgs {
                let file = msg.file().clone();
                emit_errors(&file, std::iter::once(msg));
            }
        }
    }

    fn deduplicate(&mut self, msgs: Vec<LintMsg>) -> Vec<LintMsg> {
        msgs.into_iter()
            .filter(|msg| self.lint_msgs.insert(msg.message_key()))
            .collect()
    }
}

fn make_load_error_msg(file: SourceFile, include: &Include) -> LintMsg {
    let msg = format!("Could not find file '{:?}'", include.path);
    let diagnostic = Diagnostic::error()
        .with_message(&msg)
        .with_labels(vec![Label::primary((), include.span).with_message(&msg)]);
    LintMsg::new("include_not_found", file, include.span, diagnostic)
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
        parsed_includes: HashMap::new(),
        lint_msgs: HashSet::new(),

        loader,
    };
    linter.run(&files)?;
    Ok(())
}
