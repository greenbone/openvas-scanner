use crate::{
    error::SyntaxError,
    lexer::Lexer,
    lexer::{AssignOrder, Statement},
    prefix_extension::PrefixState,
    token::{Category, Token},
    unclosed_token, unexpected_token,
};

pub(crate) trait Grouping {
    /// Parses (...)
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// Parses {...}
    fn parse_block(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// General Grouping parsing. Is called within prefix_extension.
    fn parse_grouping(&mut self, token: Token) -> Result<(PrefixState, Statement), SyntaxError>;
}

impl<'a> Lexer<'a> {
    fn parse_brace(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.statement(0, &|cat| cat == Category::RightBrace)?;
        if !end {
            Err(unclosed_token!(token))
        } else {
            self.unhandled_token = None;
            Ok(right)
        }
    }
}

impl<'a> Grouping for Lexer<'a> {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.statement(0, &|cat| cat == Category::RightParen)?;
        if !end {
            Err(unclosed_token!(token))
        } else {
            match right {
                Statement::Assign(category, _, variable, stmt) => Ok(Statement::Assign(
                    category,
                    AssignOrder::AssignReturn,
                    variable,
                    stmt,
                )),
                _ => Ok(right),
            }
        }
    }

    fn parse_block(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let mut results = vec![];
        while let Some(token) = self.token() {
            if token.category() == Category::RightCurlyBracket {
                self.unhandled_token = None;
                return Ok(Statement::Block(results));
            }
            self.unhandled_token = Some(token);
            // use min_bp 1 to skip the unhandled_token reset due to self.tokenizer.next call
            let (end, stmt) = self.statement(1, &|cat| cat == Category::Semicolon)?;
            if end && !matches!(stmt, Statement::NoOp(_)) {
                results.push(stmt);
            }
            // else error
        }
        Err(unclosed_token!(token))
    }

    fn parse_grouping(&mut self, token: Token) -> Result<(PrefixState, Statement), SyntaxError> {
        match token.category() {
            Category::LeftParen => self
                .parse_paren(token)
                .map(|stmt| (PrefixState::Continue, stmt)),
            Category::LeftCurlyBracket => self
                .parse_block(token)
                .map(|stmt| (PrefixState::Break, stmt)),
            Category::LeftBrace => self
                .parse_brace(token)
                .map(|stmt| (PrefixState::Break, stmt)),
            _ => Err(unexpected_token!(token)),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::{AssignOrder, Statement},
        parse,
        token::{Base, Category, Token},
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
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
                    Equal,
                    AssignOrder::Assign,
                    Box::new(Variable(Token {
                        category: Identifier(None),
                        position: (31, 32)
                    })),
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
                    Equal,
                    AssignOrder::Assign,
                    Box::new(Variable(Token {
                        category: Identifier(None),
                        position: (58, 59)
                    },)),
                    Box::new(Operator(
                        Minus,
                        vec![
                            Variable(Token {
                                category: Identifier(None),
                                position: (62, 63)
                            }),
                            Assign(
                                MinusMinus,
                                AssignOrder::AssignReturn,
                                Box::new(Variable(Token {
                                    category: Identifier(None),
                                    position: (68, 69)
                                },)),
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
                    Equal,
                    AssignOrder::Assign,
                    Box::new(Variable(Token {
                        category: Identifier(None),
                        position: (108, 109)
                    },)),
                    Box::new(Primitive(Token {
                        category: Number(Base10),
                        position: (112, 114)
                    }))
                )])
            ])
        );
    }
}
