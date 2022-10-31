pub mod cursor;
pub mod token;
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
