use crate::{
    parser::{AssignCategory, Statement, TokenError},
    token::{Category, Token},
    variable_extension::Variables, lexer::Lexer,
};

pub(crate) trait AssignOperator {
    fn parse_prefix_assign_operator(
        &mut self,
        token: Token,
        operation: Category,
        amount: u8,
    ) -> Result<Statement, TokenError>;
}

impl<'a> AssignOperator for Lexer<'a> {
    fn parse_prefix_assign_operator(
        &mut self,
        token: Token,
        operation: Category,
        amount: u8,
    ) -> Result<Statement, TokenError> {
        let next = self
            .next()
            .ok_or_else(|| TokenError::unexpected_end("parsing prefix statement"))?;
        match self.parse_variable(next)? {
            Statement::Variable(value) => Ok(Statement::Assign(
                AssignCategory::AssignReturn,
                value,
                Box::new(Statement::Operator(
                    operation,
                    vec![Statement::Variable(value), Statement::RawNumber(amount)],
                )),
            )),
            _ => Err(TokenError::unexpected_token(token)),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        parser::{Statement, AssignCategory},
        token::{Base, Category, Token, Tokenizer}, lexer::expression,
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn result(code: &str) -> Statement {
        let tokenizer = Tokenizer::new(code);
        expression(tokenizer).unwrap()
    }

    #[test]
    fn prefix_assignment_operator() {
        let expected = |operator: Category| {
            Operator(
                Plus,
                vec![
                    Primitive(Token {
                        category: Number(Base10),
                        position: (0, 1),
                    }),
                    Operator(
                        Star,
                        vec![
                            Assign(
                                AssignCategory::AssignReturn,
                                Token {
                                    category: Identifier(None),
                                    position: (6, 7),
                                },
                                Box::new(Operator(
                                    operator,
                                    vec![
                                        Variable(Token {
                                            category: Identifier(None),
                                            position: (6, 7),
                                        }),
                                        RawNumber(1),
                                    ],
                                )),
                            ),
                            Primitive(Token {
                                category: Number(Base10),
                                position: (10, 11),
                            }),
                        ],
                    ),
                ],
            )
        };
        assert_eq!(result("1 + ++a * 1"), expected(Plus));
        assert_eq!(result("1 + --a * 1"), expected(Minus));
    }

    #[test]
    fn postfix_assignment_operator() {
        let expected = |operator: Category| {
            Operator(
                Plus,
                vec![
                    Primitive(Token {
                        category: Number(Base10),
                        position: (0, 1),
                    }),
                    Operator(
                        Star,
                        vec![
                            Assign(
                                AssignCategory::ReturnAssign,
                                Token {
                                    category: Identifier(None),
                                    position: (4, 5),
                                },
                                Box::new(Operator(
                                    operator,
                                    vec![
                                        Variable(Token {
                                            category: Identifier(None),
                                            position: (4, 5),
                                        }),
                                        RawNumber(1),
                                    ],
                                )),
                            ),
                            Primitive(Token {
                                category: Number(Base10),
                                position: (10, 11),
                            }),
                        ],
                    ),
                ],
            )
        };
        assert_eq!(result("1 + a++ * 1"), expected(Plus));
        assert_eq!(result("1 + a-- * 1"), expected(Minus));
    }
}
