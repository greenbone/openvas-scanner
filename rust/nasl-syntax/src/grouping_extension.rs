use crate::{
    error::TokenError,
    lexer::Lexer,
    lexer::{AssignCategory, Statement},
    prefix_extension::PrefixState,
    token::{Category, Token},
    unclosed_token, unexpected_token,
};

pub(crate) trait Grouping {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, TokenError>;
    fn parse_block(&mut self, token: Token) -> Result<Statement, TokenError>;
    fn parse_grouping(&mut self, token: Token) -> Result<(PrefixState, Statement), TokenError>;
}

impl<'a> Grouping for Lexer<'a> {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, TokenError> {
        let lhs = self.expression_bp(0, Category::RightParen)?;
        let actual = self
            .unhandled_token
            .map_or(Category::Equal, |t| t.category());
        if actual != Category::RightParen {
            Err(unclosed_token!(token))
        } else {
            self.unhandled_token = None;
            match lhs {
                Statement::Assign(_, token, stmt) => {
                    Ok(Statement::Assign(AssignCategory::AssignReturn, token, stmt))
                }
                _ => Ok(lhs),
            }
        }
    }

    fn parse_block(&mut self, token: Token) -> Result<Statement, TokenError> {
        let mut results = vec![];
        while let Some(token) = self.tokenizer.next() {
            if token.category() == Category::RightCurlyBracket {
                self.unhandled_token = None;
                return Ok(Statement::Block(results));
            }
            self.unhandled_token = Some(token);
            results.push(self.expression_bp(0, Category::Semicolon)?);
        }
        Err(unclosed_token!(token))
    }

    fn parse_grouping(&mut self, token: Token) -> Result<(PrefixState, Statement), TokenError> {
        match token.category() {
            Category::LeftParen => self
                .parse_paren(token)
                .map(|stmt| (PrefixState::Continue, stmt)),
            Category::LeftCurlyBracket => self
                .parse_block(token)
                .map(|stmt| (PrefixState::Break, stmt)),
            _ => Err(unexpected_token!(token)),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::Statement,
        lexer::{expression, AssignCategory},
        token::{Base, Category, Token, Tokenizer},
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn result(code: &str) -> Statement {
        let tokenizer = Tokenizer::new(code);
        expression(tokenizer).unwrap()
    }

    #[test]
    fn variables() {
        assert_eq!(
            result(
                r"
            {
                a = b + 1;
                b = a - --c;
                {
                   d = 23;
                }
            }
            "
            ),
            Block(vec![
                Assign(
                    AssignCategory::Assign,
                    Token {
                        category: Identifier(None),
                        position: (31, 32)
                    },
                    Box::new(Operator(
                        Plus,
                        vec![
                            Variable(Token {
                                category: Identifier(None),
                                position: (35, 36)
                            }),
                            Primitive(Token {
                                category: Number(Base10),
                                position: (39, 40)
                            })
                        ]
                    ))
                ),
                Assign(
                    AssignCategory::Assign,
                    Token {
                        category: Identifier(None),
                        position: (58, 59)
                    },
                    Box::new(Operator(
                        Minus,
                        vec![
                            Variable(Token {
                                category: Identifier(None),
                                position: (62, 63)
                            }),
                            Assign(
                                AssignCategory::AssignReturn,
                                Token {
                                    category: Identifier(None),
                                    position: (68, 69)
                                },
                                Box::new(Operator(
                                    Minus,
                                    vec![
                                        Variable(Token {
                                            category: Identifier(None),
                                            position: (68, 69)
                                        }),
                                        RawNumber(1)
                                    ]
                                ))
                            )
                        ]
                    ))
                ),
                Block(vec![Assign(
                    AssignCategory::Assign,
                    Token {
                        category: Identifier(None),
                        position: (108, 109)
                    },
                    Box::new(Primitive(Token {
                        category: Number(Base10),
                        position: (112, 114)
                    }))
                )])
            ])
        );
    }
}
