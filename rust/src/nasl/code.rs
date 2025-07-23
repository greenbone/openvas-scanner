use std::path::{Path, PathBuf};

use codespan_reporting::files::SimpleFile;

use super::{
    Loader,
    error::Level,
    syntax::{DescriptionBlock, LoadError, ParseError, Parser, Tokenizer, grammar::Ast},
};

fn parse(code: &str) -> Result<Ast, Vec<ParseError>> {
    let tokenizer = Tokenizer::tokenize(code);
    let parser = Parser::new(tokenizer);
    parser.parse_program()
}

fn parse_description_block(code: &str) -> Result<Ast, Vec<ParseError>> {
    let tokenizer = Tokenizer::tokenize(code);
    let mut parser = Parser::new(tokenizer);
    let result: Result<DescriptionBlock, ParseError> =
        parser.parse_span().map_err(|e| e.unwrap_as_spanned());
    result
        .map(|metadata| metadata.into_ast())
        .map_err(|e| vec![e])
}

pub type SourceFile = SimpleFile<String, String>;

pub struct ParseResult {
    result: Result<Ast, Vec<ParseError>>,
    file: SourceFile,
}

impl ParseResult {
    fn new(code: &str, path: &Path) -> Self {
        Self::new_with_parse_fn(code, path, parse)
    }

    fn new_with_parse_fn(
        code: &str,
        path: &Path,
        f: impl Fn(&str) -> Result<Ast, Vec<ParseError>>,
    ) -> Self {
        let file = SimpleFile::new(path.to_string_lossy().into(), code.to_owned());
        let result = f(code);
        Self { file, result }
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

    pub fn emit_errors(self) -> Result<Ast, Vec<ParseError>> {
        match self.result {
            Ok(result) => Ok(result),
            Err(errors) => {
                super::error::emit_errors(&self.file, errors.iter().cloned(), Level::Error);
                Err(errors)
            }
        }
    }

    pub fn emit_errors_get_ast_and_file(self) -> Result<(Ast, SourceFile), Vec<ParseError>> {
        match self.result {
            Ok(result) => Ok((result, self.file)),
            Err(errors) => {
                super::error::emit_errors(&self.file, errors.iter().cloned(), Level::Error);
                Err(errors)
            }
        }
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

    pub fn from_string_filename(code: &str, filename: impl AsRef<Path>) -> Self {
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
            None => ParseResult::new(&self.code, Path::new("")),
        }
    }

    pub fn parse_description_block(self) -> ParseResult {
        let path = self.path.unwrap_or(Path::new("").to_owned());
        ParseResult::new_with_parse_fn(&self.code, &path, parse_description_block)
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

#[cfg(test)]
use tokenize::TokenizeResult;

#[cfg(test)]
mod tokenize {
    use std::path::Path;

    use codespan_reporting::files::SimpleFile;
    use itertools::{Either, Itertools};

    use crate::nasl::{
        error::Level,
        syntax::{Token, Tokenizer, TokenizerError},
    };

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

        pub fn emit_errors(self) -> Option<Vec<Token>> {
            match self.result {
                Ok(result) => Some(result),
                Err(errors) => {
                    error::emit_errors(&self.file, errors.into_iter(), Level::Error);
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
