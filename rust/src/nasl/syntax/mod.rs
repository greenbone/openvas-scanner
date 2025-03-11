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
mod variable_extension;

use std::path::Path;

pub use crate::storage::item::ACT;
use codespan_reporting::files::SimpleFiles;
pub use error::{ErrorKind, SyntaxError};
pub use lexer::Lexer;
pub use loader::*;
pub use naslvalue::*;
pub use statement::*;
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

// TODO remove
// This is a helper method while the code structure isnt the way I want it to be
pub fn parse_return_first(code: &str) -> Statement {
    parse(code).unwrap().remove(0)
}

// TODO remove
// This is a helper method while the code structure isnt the way I want it to be
pub fn parse_only_first_error(code: &str) -> Result<Vec<Statement>, SyntaxError> {
    parse(code).map_err(|mut e| e.remove(0))
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
    use crate::nasl::syntax::{
        token::{Keyword, Token, TokenKind},
        Tokenizer,
    };

    #[test]
    fn use_tokenizer() {
        let all_tokens = Tokenizer::tokenize("local_var hello = 'World!';").unwrap();
        assert_eq!(
            all_tokens,
            vec![
                Token {
                    kind: TokenKind::Identifier(Keyword::LocalVar),
                    position: (0, 9)
                },
                Token {
                    kind: TokenKind::Identifier(Keyword::Undefined("hello".to_owned())),
                    position: (10, 15)
                },
                Token {
                    kind: TokenKind::Equal,
                    position: (16, 17)
                },
                Token {
                    kind: TokenKind::Data("World!".as_bytes().to_vec()),
                    position: (18, 26)
                },
                Token {
                    kind: TokenKind::Semicolon,
                    position: (26, 27)
                },
            ]
        );
    }

    #[test]
    fn use_parser() {
        let code = "a = 23;b = 1;";
        let expected = ["a = 23;", "b = 1;"];
        for (i, stmt) in super::parse(code).unwrap().into_iter().enumerate() {
            assert_eq!(&code[stmt.range()], expected[i]);
        }
    }
}
