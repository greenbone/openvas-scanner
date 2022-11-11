use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::Lexer,
    lexer::Statement,
    token::{Category, Token},
    unexpected_end, unexpected_token,
};

pub(crate) trait Variables {
    /// Parses variables, function calls.
    fn parse_variable(&mut self, token: Token) -> Result<Statement, SyntaxError>;
}

impl<'a> Variables for Lexer<'a> {
    fn parse_variable(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        if token.category() != Category::Identifier(None) {
            return Err(unexpected_token!(token));
        }

        if let Some(nt) = self.token() {
            match nt.category() {
                Category::LeftParen => {
                    let parameter = self.parse_paren(nt)?;
                    return Ok(Statement::Call(token, Box::new(parameter)));
                }
                Category::DoublePoint => {
                    let either_comma_rightparen =
                        |cat| matches!(cat, Category::RightParen | Category::Comma);
                    let expr = self.statement(0, &either_comma_rightparen)?;
                    // maybe it makes sense to move that check to the statement method?
                    if let Some(end) = self.end_category {
                        if either_comma_rightparen(end) {
                            return Ok(Statement::NamedParameter(token, Box::new(expr)));
                        } else {
                            return Err(unexpected_token!(self.unhandled_token.unwrap()));
                        }
                    } else {
                        return Err(unexpected_end!("parsing named variable"));
                    }
                }
                _ => self.unhandled_token = Some(nt),
            }
        }
        Ok(Statement::Variable(token))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::Statement,
        parse,
        token::{Base, Category, StringCategory, Token},
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn token(category: Category, start: usize, end: usize) -> Token {
        Token {
            category,
            position: (start, end),
        }
    }

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn variables() {
        assert_eq!(result("a"), Variable(token(Identifier(None), 0, 1)));
    }

    #[test]
    fn anon_function_call() {
        let fn_name = token(Identifier(None), 0, 1);
        let args = Box::new(Parameter(vec![
            Primitive(token(Number(Base10), 2, 3)),
            Primitive(token(Number(Base10), 5, 6)),
            Primitive(token(Number(Base10), 8, 9)),
        ]));

        assert_eq!(result("a(1, 2, 3)"), Call(fn_name, args));
    }

    #[test]
    fn named_function_call() {
        use Statement::*;
        assert_eq!(
            result("script_tag(name:\"cvss_base\", value:1 + 1 % 2);"),
            Call(
                Token {
                    category: Identifier(None),
                    position: (0, 10)
                },
                Box::new(Parameter(vec![
                    NamedParameter(
                        Token {
                            category: Identifier(None),
                            position: (11, 15)
                        },
                        Box::new(Primitive(Token {
                            category: String(StringCategory::Unquoteable),
                            position: (17, 26)
                        }))
                    ),
                    NamedParameter(
                        Token {
                            category: Identifier(None),
                            position: (29, 34)
                        },
                        Box::new(Operator(
                            Plus,
                            vec![
                                Primitive(Token {
                                    category: Number(Base10),
                                    position: (35, 36)
                                }),
                                Operator(
                                    Percent,
                                    vec![
                                        Primitive(Token {
                                            category: Number(Base10),
                                            position: (39, 40)
                                        }),
                                        Primitive(Token {
                                            category: Number(Base10),
                                            position: (43, 44)
                                        })
                                    ]
                                )
                            ]
                        ))
                    )
                ]))
            )
        );

        assert_eq!(
            result("script_tag(name: 2);"),
            Call(
                Token {
                    category: Identifier(None),
                    position: (0, 10)
                },
                Box::new(NamedParameter(
                    Token {
                        category: Identifier(None),
                        position: (11, 15)
                    },
                    Box::new(Primitive(Token {
                        category: Number(Base10),
                        position: (17, 18)
                    }))
                ))
            )
        );
    }
}
