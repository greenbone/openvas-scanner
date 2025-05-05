use std::path::{Path, PathBuf};

use codespan_reporting::files::SimpleFile;

use super::{
    Loader,
    syntax::{
        Ast, LoadError, Tokenizer,
        parser::{ParseError, Parser},
    },
};

fn parse(code: &str) -> Result<Ast, Vec<ParseError>> {
    let tokenizer = Tokenizer::tokenize(code);
    let mut parser = Parser::new(tokenizer);
    parser.parse_program()
}

pub type SourceFile = SimpleFile<String, String>;

pub struct ParseResult {
    result: Result<Ast, Vec<ParseError>>,
    file: SourceFile,
}

impl ParseResult {
    pub fn new(code: &str, path: &Path) -> Self {
        let file = SimpleFile::new(path.to_string_lossy().into(), code.to_owned());
        let result = parse(code);
        Self { file, result }
    }

    pub fn new_without_file(code: &str) -> Self {
        Self::new(code, Path::new(""))
    }

    pub fn result(self) -> Result<Ast, Vec<ParseError>> {
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
                super::error::emit_errors(&self.file, errors.into_iter());
                None
            }
        }
    }

    #[cfg(test)]
    pub fn unwrap_errors_str(self) -> String {
        let errs = self.result.unwrap_err();
        super::error::emit_errors_str(&self.file, errs.into_iter())
    }

    pub fn file(&self) -> &SourceFile {
        &self.file
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

    pub fn from_string_fake_filename(code: &str, filename: impl AsRef<Path>) -> Self {
        Self {
            code: code.to_string(),
            path: Some(filename.as_ref().to_owned()),
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

    pub fn code(&self) -> &str {
        &self.code
    }
}

#[cfg(test)]
pub use tokenize::TokenizeResult;

#[cfg(test)]
mod tokenize {
    use std::path::Path;

    use codespan_reporting::files::SimpleFile;
    use itertools::{Either, Itertools};

    use crate::nasl::syntax::{Token, Tokenizer, TokenizerError};

    use super::{super::error, SourceFile};

    fn split_tokens_and_errors(tokenizer: Tokenizer) -> Result<Vec<Token>, Vec<TokenizerError>> {
        let (tokens, errors): (Vec<_>, Vec<_>) = tokenizer.partition_map(|a| match a {
            Ok(a) => Either::Left(a),
            Err(a) => Either::Right(a),
        });
        if !errors.is_empty() {
            Err(errors)
        } else {
            Ok(tokens)
        }
    }

    pub struct TokenizeResult {
        result: Result<Vec<Token>, Vec<TokenizerError>>,
        file: SourceFile,
    }

    impl TokenizeResult {
        pub fn new(code: &str, path: &Path) -> Self {
            let file = SimpleFile::new(path.to_string_lossy().into(), code.to_owned());
            let result = split_tokens_and_errors(Tokenizer::tokenize(code));
            Self { file, result }
        }

        pub fn result(self) -> Result<Vec<Token>, Vec<TokenizerError>> {
            self.result
        }

        pub fn emit_errors(self) -> Option<Vec<Token>> {
            match self.result {
                Ok(result) => Some(result),
                Err(errors) => {
                    error::emit_errors(&self.file, errors.into_iter());
                    None
                }
            }
        }

        pub fn unwrap_errors_str(self) -> String {
            let errs = self.result.unwrap_err();
            error::emit_errors_str(&self.file, errs.into_iter())
        }
    }
}
