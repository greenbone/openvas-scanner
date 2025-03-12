use std::{
    path::{Path, PathBuf},
    vec,
};

use codespan_reporting::files::SimpleFiles;

use super::{
    syntax::{Lexer, LoadError, Statement, SyntaxError, Tokenizer},
    Loader,
};

pub fn read_single_files(file_name: &Path, code: &str) -> (SimpleFiles<String, String>, usize) {
    let mut files = SimpleFiles::new();
    let file_id = files.add(
        file_name.as_os_str().to_string_lossy().to_string(),
        code.to_owned(),
    );
    (files, file_id)
}

#[derive(Clone, Debug)]
pub struct Ast {
    stmts: Vec<Statement>,
    position: usize,
}

impl IntoIterator for Ast {
    type Item = Statement;

    type IntoIter = vec::IntoIter<Statement>;

    fn into_iter(self) -> Self::IntoIter {
        self.stmts.into_iter()
    }
}

impl Ast {
    fn new(stmts: Vec<Statement>) -> Self {
        Self { stmts, position: 0 }
    }

    pub fn stmts(self) -> Vec<Statement> {
        self.stmts
    }

    fn next(&mut self) -> Option<Statement> {
        let stmt = self.stmts.get(self.position);
        self.position += 1;
        stmt.cloned()
    }
}

fn parse(code: &str) -> Result<Ast, Vec<SyntaxError>> {
    let tokens = Tokenizer::tokenize(code).map_err(|e| {
        e.into_iter()
            .map(|e| SyntaxError::from(e))
            .collect::<Vec<_>>()
    })?;
    let lexer = Lexer::new(tokens);
    let results = lexer.collect::<Result<Vec<_>, _>>();
    // TODO support multiple errors
    results.map_err(|e| vec![e]).map(|stmts| Ast::new(stmts))
}

pub struct ParseResult {
    result: Result<Ast, Vec<SyntaxError>>,
    files: SimpleFiles<String, String>,
    file_id: usize,
}

impl ParseResult {
    pub fn new(code: &str, path: &Path) -> Self {
        let (files, file_id) = read_single_files(path, code);
        let result = parse(code);
        Self {
            files,
            file_id,
            result,
        }
    }

    pub fn new_without_file(code: &str) -> Self {
        Self::new(code, Path::new(""))
    }

    pub fn result(self) -> Result<Ast, Vec<SyntaxError>> {
        self.result
    }

    pub fn num_errors(&self) -> usize {
        match &self.result {
            Ok(_) => 0,
            Err(errs) => errs.len(),
        }
    }

    pub fn emit_errors(self) -> Option<Ast> {
        match self.result {
            Ok(result) => Some(result),
            Err(errors) => {
                super::error::emit_errors(&self.files, self.file_id, errors.into_iter());
                None
            }
        }
    }

    pub fn unwrap_stmts(self) -> Vec<Statement> {
        self.result.unwrap().stmts
    }
}

pub struct Code {
    code: String,
    path: Option<PathBuf>,
}

impl Code {
    pub fn load(loader: &dyn Loader, path: impl AsRef<Path>) -> Result<Self, LoadError> {
        Ok(Self {
            code: loader.load(&path.as_ref().to_string_lossy())?,
            path: Some(path.as_ref().to_owned()),
        })
    }

    pub fn from_string(code: &str) -> Self {
        Self {
            path: None,
            code: code.to_string(),
        }
    }

    pub fn from_string_fake_filename(code: &str, filename: &str) -> Self {
        Self {
            code: code.to_string(),
            path: Some(Path::new(filename).to_owned()),
        }
    }

    #[cfg(test)]
    pub fn tokenize(self) -> TokenizeResult {
        match self.path {
            Some(path) => TokenizeResult::new(&self.code, &path),
            None => unimplemented!(),
        }
    }

    pub fn parse(self) -> ParseResult {
        match self.path {
            Some(path) => ParseResult::new(&self.code, &path),
            None => ParseResult::new_without_file(&self.code),
        }
    }
}

#[cfg(test)]
pub use tokenize::TokenizeResult;

#[cfg(test)]
mod tokenize {
    use std::path::Path;

    use codespan_reporting::files::SimpleFiles;

    use crate::nasl::syntax::{Token, Tokenizer, TokenizerError};

    use super::{super::error, read_single_files};

    pub struct TokenizeResult {
        result: Result<Vec<Token>, Vec<TokenizerError>>,
        files: SimpleFiles<String, String>,
        file_id: usize,
    }

    impl TokenizeResult {
        pub fn new(code: &str, path: &Path) -> Self {
            let (files, file_id) = read_single_files(path, code);
            let result = Tokenizer::tokenize(code);
            Self {
                files,
                file_id,
                result,
            }
        }

        pub fn result(self) -> Result<Vec<Token>, Vec<TokenizerError>> {
            self.result
        }

        pub fn emit_errors(self) -> Option<Vec<Token>> {
            match self.result {
                Ok(result) => Some(result),
                Err(errors) => {
                    error::emit_errors(&self.files, self.file_id, errors.into_iter());
                    None
                }
            }
        }
    }
}
