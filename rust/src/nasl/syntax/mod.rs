// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
mod cursor;
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
mod variable_extension;

pub use crate::storage::item::ACT;
pub use error::{ErrorKind, SyntaxError};
pub use lexer::Lexer;
pub use loader::*;
pub use naslvalue::*;
pub use statement::*;
pub use token::Keyword;
pub use token::Token;
pub use token::TokenKind;
pub use tokenizer::Tokenizer;

/// Parses given code and returns found Statements and Errors
///
/// # Examples
/// Basic usage:
///
/// ```
/// use scannerlib::nasl::syntax::{Statement, SyntaxError, parse};
/// let statements =
///     parse("a = 23;b = 1;").collect::<Vec<Result<Statement, SyntaxError>>>();
/// ````
pub fn parse(code: &str) -> impl Iterator<Item = Result<Statement, SyntaxError>> + '_ {
    // TODO Do not unwrap here, handle errors properly.
    let tokens = Tokenizer::tokenize(code).unwrap();
    Lexer::new(tokens)
}

#[cfg(test)]
mod tests {
    use crate::nasl::syntax::{
        cursor::Cursor,
        token::{Keyword, Token, TokenKind},
        Tokenizer,
    };

    #[test]
    fn use_cursor() {
        let mut cursor = Cursor::new("  \n\tdisplay(12);");
        cursor.skip_while(|c| c.is_whitespace());
        assert_eq!(cursor.advance(), Some('d'));
    }

    #[test]
    fn use_tokenizer() {
        let all_tokens = Tokenizer::tokenize("local_var hello = 'World!';").unwrap();
        assert_eq!(
            all_tokens,
            vec![
                Token {
                    kind: TokenKind::Identifier(Keyword::LocalVar),
                    line_column: (1, 1),
                    position: (0, 9)
                },
                Token {
                    kind: TokenKind::Identifier(Keyword::Undefined("hello".to_owned())),
                    line_column: (1, 11),
                    position: (10, 15)
                },
                Token {
                    kind: TokenKind::Equal,
                    line_column: (1, 17),
                    position: (16, 17)
                },
                Token {
                    kind: TokenKind::Data("World!".as_bytes().to_vec()),
                    line_column: (1, 19),
                    position: (18, 26)
                },
                Token {
                    kind: TokenKind::Semicolon,
                    line_column: (1, 27),
                    position: (26, 27)
                },
            ]
        );
    }

    #[test]
    fn use_parser() {
        let code = "a = 23;b = 1;";
        let expected = ["a = 23;", "b = 1;"];
        for (i, s) in super::parse(code).enumerate() {
            let stmt = s.unwrap();
            //assert!(matches!(stmt.kind(), Assign(..)));
            assert_eq!(&code[stmt.range()], expected[i]);
        }
    }
}
