//! nasl_syntax is a library to parse nasl scripts to statements for further usage.
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

pub use error::TokenError;
pub use lexer::Statement;
pub use token::Category as TokenCategory;
pub use token::Token;

/// Parses given code and returns all found Statements and Errors
///
/// # Examples
/// Basic usage:
///
/// ```
/// nasl_syntax::parse("a = 23;b = 1;");
/// ````
pub fn parse(code: &str) -> Vec<Result<Statement, TokenError>> {
    use lexer::Lexer;
    use token::Tokenizer;
    let tokenizer = Tokenizer::new(code);
    let mut lexer = Lexer::new(tokenizer);
    let mut results = vec![];
    loop {
        let result = lexer.expression_bp(0, TokenCategory::Semicolon);
        if result == Ok(Statement::EoF) {
            break;
        }
        results.push(result);
    }
    results
}

#[cfg(test)]
mod tests {
    use crate::{
        cursor::Cursor,
        token::{Category, Keyword, StringCategory, Token, Tokenizer},
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
}
