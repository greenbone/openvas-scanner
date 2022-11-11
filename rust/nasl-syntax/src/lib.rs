//! nasl_syntax is a library to parse nasl scripts to statements for further usage.
#![warn(missing_docs)]
mod cursor;
mod error;
mod grouping_extension;
mod infix_extension;
mod keyword_extension;
mod lexer;
mod operation;
mod postifx_extension;
mod prefix_extension;
mod token;
mod variable_extension;

pub use error::SyntaxError;
pub use lexer::Statement;
pub use token::Category as TokenCategory;
pub use token::Token;

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
    use lexer::Lexer;
    use token::Tokenizer;
    let tokenizer = Tokenizer::new(code);
    Lexer::new(tokenizer)
}

#[cfg(test)]
mod tests {
    use crate::{
        cursor::Cursor,
        lexer::AssignOrder,
        token::{Base, Category, Keyword, StringCategory, Token, Tokenizer},
        Statement, SyntaxError,
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
                    category: Category::Identifier(Some(Keyword::LocalVar)),
                    position: (0, 9)
                },
                Token {
                    category: Category::Identifier(None),
                    position: (10, 15)
                },
                Token {
                    category: Category::Equal,
                    position: (16, 17)
                },
                Token {
                    category: Category::String(StringCategory::Quoteable),
                    position: (19, 25)
                },
                Token {
                    category: Category::Semicolon,
                    position: (26, 27)
                }
            ]
        );
    }

    #[test]
    fn use_parser() {
        use Category::*;
        use Statement::*;
        let statements =
            super::parse("a = 23;b = 1;").collect::<Vec<Result<Statement, SyntaxError>>>();
        assert_eq!(
            statements,
            vec![
                Ok(Assign(
                    Equal,
                    AssignOrder::Assign,
                    Token {
                        category: Identifier(None),
                        position: (0, 1)
                    },
                    Box::new(Primitive(Token {
                        category: Number(Base::Base10),
                        position: (4, 6)
                    }))
                )),
                Ok(Assign(
                    Equal,
                    AssignOrder::Assign,
                    Token {
                        category: Identifier(None),
                        position: (7, 8)
                    },
                    Box::new(Primitive(Token {
                        category: Number(Base::Base10),
                        position: (11, 12)
                    }))
                ))
            ]
        );
    }
}
