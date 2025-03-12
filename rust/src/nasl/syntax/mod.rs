// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
mod error;
mod grouping_extension;
mod keyword_extension;
mod lexer;
mod loader;
mod naslvalue;
mod operation;
mod prefix_extension;
mod statement;
mod token;
mod tokenizer;
mod utils;

use std::path::Path;

pub use crate::storage::item::ACT;
use codespan_reporting::files::SimpleFiles;
pub use error::{ErrorKind, SyntaxError};
pub use lexer::Lexer;
pub use loader::*;
pub use naslvalue::*;
pub use statement::*;
pub use token::Ident;
pub use token::Keyword;
pub use token::Token;
pub use token::TokenKind;
pub use tokenizer::Tokenizer;
pub use tokenizer::TokenizerError;
use utils::read_single_files;

type ParseResult = Result<Vec<Statement>, Vec<SyntaxError>>;

pub fn parse(code: &str) -> ParseResult {
    let tokens = Tokenizer::tokenize(code).map_err(|e| {
        e.into_iter()
            .map(|e| SyntaxError::from(e))
            .collect::<Vec<_>>()
    })?;
    let lexer = Lexer::new(tokens);
    let results = lexer.collect::<Result<Vec<_>, _>>();
    // TODO support multiple errors
    let results = results.map_err(|e| vec![e])?;
    Ok(results)
}

pub struct ParseInfo {
    pub result: ParseResult,
    files: SimpleFiles<String, String>,
    file_id: usize,
}

impl ParseInfo {
    pub fn new(code: &str, path: &Path) -> Self {
        let (files, file_id) = read_single_files(path, code);
        let result = parse(code);
        Self {
            files,
            file_id,
            result,
        }
    }

    pub fn emit_errors(self) {
        super::error::emit_errors(
            &self.files,
            self.file_id,
            self.result.unwrap_err().into_iter(),
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn use_parser() {
        let code = "a = 23;b = 1;";
        let expected = ["a = 23;", "b = 1;"];
        for (i, stmt) in super::parse(code).unwrap().into_iter().enumerate() {
            assert_eq!(&code[stmt.range()], expected[i]);
        }
    }
}
