// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
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
mod variable_extension;
// should be replaced with tracing
pub mod logger;

pub use error::{ErrorKind, SyntaxError};
pub use lexer::Lexer;
pub use loader::*;
pub use naslvalue::*;
pub use statement::*;
pub use storage::item::ACT;
pub use token::Base as NumberBase;
pub use token::Category as TokenCategory;
pub use token::IdentifierType;
pub use token::Token;
pub use token::Tokenizer;

/// Parses given code and returns found Statements and Errors
///
/// # Examples
/// Basic usage:
///
/// ```
/// use nasl_syntax::{Statement, SyntaxError};
/// let statements =
///     nasl_syntax::parse("a = 23;b = 1;").collect::<Vec<Result<Statement, SyntaxError>>>();
/// ````
pub fn parse(code: &str) -> impl Iterator<Item = Result<Statement, SyntaxError>> + '_ {
    let tokenizer = Tokenizer::new(code);
    Lexer::new(tokenizer)
}

#[cfg(test)]
mod tests {
    use crate::{
        cursor::Cursor,
        token::{Category, IdentifierType, Token, Tokenizer},
    };

    #[test]
    fn use_cursor() {
        let mut cursor = Cursor::new("  \n\tdisplay(12);");
        cursor.skip_while(|c| c.is_whitespace());
        assert_eq!(cursor.advance(), Some('d'));
    }

    #[test]
    fn use_tokenizer() {
        let tokenizer = Tokenizer::new("local_var hello = 'World!';");
        let all_tokens = tokenizer.collect::<Vec<Token>>();
        assert_eq!(
            all_tokens,
            vec![
                Token {
                    category: Category::Identifier(IdentifierType::LocalVar),
                    line_column: (1, 1),
                    position: (0, 9)
                },
                Token {
                    category: Category::Identifier(IdentifierType::Undefined("hello".to_owned())),
                    line_column: (1, 11),
                    position: (10, 15)
                },
                Token {
                    category: Category::Equal,
                    line_column: (1, 17),
                    position: (16, 17)
                },
                Token {
                    category: Category::Data("World!".as_bytes().to_vec()),
                    line_column: (1, 19),
                    position: (18, 26)
                },
                Token {
                    category: Category::Semicolon,
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
