use crate::{
    error::TokenError,
    grouping_extension::Grouping,
    lexer::Lexer,
    lexer::Statement,
    prefix_extension::PrefixState,
    token::{Category, Keyword, Token},
    unexpected_end, unexpected_token,
};

pub(crate) trait Keywords {
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(PrefixState, Statement), TokenError>;
}

impl<'a> Lexer<'a> {
    fn parse_if(&mut self) -> Result<(PrefixState, Statement), TokenError> {
        let token = self.next().ok_or_else(|| unexpected_end!("if parsing"))?;
        let condition = match token.category() {
            Category::LeftParen => self.parse_paren(token),
            _ => Err(unexpected_token!(token)),
        }?;
        // TODO add block handling and error handling
        let body = self.expression_bp(0, Category::Semicolon)?;
        let r#else: Option<Statement> = {
            match self.next() {
                Some(token) => match token.category() {
                    Category::Identifier(Some(Keyword::Else)) => {
                        Some(self.expression_bp(0, Category::Semicolon)?)
                    }
                    _ => {
                        self.unhandled_token = Some(token);
                        None
                    }
                },
                None => None,
            }
        };
        Ok((
            PrefixState::Break,
            Statement::If(Box::new(condition), Box::new(body), r#else.map(Box::new)),
        ))
    }
}

impl<'a> Keywords for Lexer<'a> {
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(PrefixState, Statement), TokenError> {
        match keyword {
            Keyword::For => todo!(),
            Keyword::ForEach => todo!(),
            Keyword::If => self.parse_if(),
            Keyword::Else => Err(unexpected_token!(token)), // handled in if
            Keyword::While => todo!(),
            Keyword::Repeat => todo!(),
            Keyword::Until => todo!(),
            Keyword::LocalVar => todo!(),
            Keyword::GlobalVar => todo!(),
            Keyword::Null => todo!(),
            Keyword::Return => todo!(),
            Keyword::Include => todo!(),
            Keyword::Exit => todo!(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::expression,
        lexer::Statement,
        token::{Category, StringCategory, Token, Tokenizer},
    };

    use Category::*;
    use Statement::*;

    #[test]
    fn if_statement() {
        let tokenizer = Tokenizer::new("if (description) script_oid('1');");
        let actual = expression(tokenizer).unwrap();
        assert_eq!(
            actual,
            If(
                Box::new(Variable(Token {
                    category: Identifier(None),
                    position: (4, 15)
                })),
                Box::new(Call(
                    Token {
                        category: Identifier(None),
                        position: (17, 27)
                    },
                    Box::new(Primitive(Token {
                        category: String(StringCategory::Quoteable),
                        position: (29, 30)
                    }))
                )),
                None
            )
        );
    }
}
