use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    token::{Category, Token},
    unclosed_token, unexpected_token, Statement,
};

pub(crate) trait Variables {
    /// Parses variables, function calls.
    fn parse_variable(&mut self, token: Token) -> Result<(End, Statement), SyntaxError>;
}

pub(crate) trait CommaGroup {
    fn parse_comma_group(
        &mut self,
        category: Category,
    ) -> Result<(End, Vec<Statement>), SyntaxError>;
}

impl<'a> CommaGroup for Lexer<'a> {
    #[inline(always)]
    fn parse_comma_group(
        &mut self,
        category: Category,
    ) -> Result<(End, Vec<Statement>), SyntaxError> {
        let mut params = vec![];
        let mut end = End::Continue;
        while let Some(token) = self.peek() {
            if *token.category() == category {
                self.token();
                end = End::Done(category);
                break;
            }
            let (stmtend, param) = self.statement(0, &|c| c == &category || c == &Category::Comma)?;
            match param {
                Statement::Parameter(nparams) => params.extend_from_slice(&nparams),
                param => params.push(param),
            }
            match stmtend {
                End::Done(endcat) => {
                    if endcat == category {
                        end = End::Done(category);
                        break;
                    }
                }
                End::Continue => {}
            };
        }
        Ok((end, params))
    }
}

impl<'a> Variables for Lexer<'a> {
    fn parse_variable(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        if !matches!(token.category(), Category::Identifier(crate::IdentifierType::Undefined(_))) {
            return Err(unexpected_token!(token));
        }
        use End::*;

        if let Some(nt) = self.peek() {
            match nt.category() {
                Category::LeftParen => {
                    self.token();
                    let (end, params) = self.parse_comma_group(Category::RightParen)?;
                    if end == End::Continue {
                        return Err(unclosed_token!(token));
                    }
                    return Ok((
                        Continue,
                        Statement::Call(token, Box::new(Statement::Parameter(params))),
                    ));
                }
                Category::LeftBrace => {
                    self.token();
                    let (end, lookup) = self.statement(0, &|c| c == &Category::RightBrace)?;
                    let lookup = lookup.as_returnable_or_err()?;
                    if end == End::Continue {
                        return Err(unclosed_token!(token));
                    } else {
                        return Ok((Continue, Statement::Array(token, Some(Box::new(lookup)))));
                    }
                }
                _ => {},
            }
        }
        Ok((Continue, Statement::Variable(token)))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        {AssignOrder, Statement},
        parse,
        token::{Category, Token},
    };

    
    use Category::*;
    use Statement::*;
    use crate::IdentifierType::*;

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
        assert_eq!(result("a;"), Variable(token(Identifier(Undefined("a".to_owned())), 1, 1)));
    }

    #[test]
    fn arrays() {
        assert_eq!(
            result("a[0];"),
            Array(
                token(Identifier(Undefined("a".to_owned())), 1, 1),
                Some(Box::new(Primitive(token(Number(0), 1, 3))))
            )
        );

        assert_eq!(
            result("a = [1, 2, 3];"),
            Assign(
                Equal,
                AssignOrder::AssignReturn,
                Box::new(Array(
                    Token {
                        category: Identifier(Undefined("a".to_owned())),
                        position: (1, 1)
                    },
                    None
                )),
                Box::new(Parameter(vec![
                    Primitive(Token {
                        category: Number(1),
                        position: (1, 6)
                    }),
                    Primitive(Token {
                        category: Number(2),
                        position: (1, 9)
                    }),
                    Primitive(Token {
                        category: Number(3),
                        position: (1, 12)
                    })
                ]))
            )
        );

        assert_eq!(
            result("a[0] = [1, 2, 4];"),
            Assign(
                Equal,
                AssignOrder::AssignReturn,
                Box::new(Array(
                    Token {
                        category: Identifier(Undefined("a".to_owned())),
                        position: (1, 1)
                    },
                    Some(Box::new(Primitive(Token {
                        category: Number(0),
                        position: (1, 3)
                    })))
                )),
                Box::new(Parameter(vec![
                    Primitive(Token {
                        category: Number(1),
                        position: (1, 9)
                    }),
                    Primitive(Token {
                        category: Number(2),
                        position: (1, 12)
                    }),
                    Primitive(Token {
                        category: Number(4),
                        position: (1, 15)
                    })
                ]))
            )
        );
    }

    #[test]
    fn anon_function_call() {
        let fn_name = token(Identifier(Undefined("a".to_owned())), 1, 1);
        let args = Box::new(Parameter(vec![
            Primitive(token(Number(1), 1, 3)),
            Primitive(token(Number(2), 1, 6)),
            Primitive(token(Number(3), 1, 9)),
        ]));

        assert_eq!(result("a(1, 2, 3);"), Call(fn_name, args));
    }

    #[test]
    fn named_function_call() {
        use Statement::*;
        assert_eq!(
            result("script_tag(name:\"cvss_base\", value:1 + 1 % 2);"),
            Call(
                Token {
                    category: Identifier(Undefined("script_tag".to_owned())),
                    position: (1, 1)
                },
                Box::new(Parameter(vec![
                    NamedParameter(
                        Token {
                            category: Identifier(Undefined("name".to_owned())),
                            position: (1, 12)
                        },
                        Box::new(Primitive(Token {
                            category: String("cvss_base".to_owned()),
                            position: (1, 17)
                        }))
                    ),
                    NamedParameter(
                        Token {
                            category: Identifier(Undefined("value".to_owned())),
                            position: (1, 30)
                        },
                        Box::new(Operator(
                            Plus,
                            vec![
                                Primitive(Token {
                                    category: Number(1),
                                    position: (1, 36)
                                }),
                                Operator(
                                    Percent,
                                    vec![
                                        Primitive(Token {
                                            category: Number(1),
                                            position: (1, 40)
                                        }),
                                        Primitive(Token {
                                            category: Number(2),
                                            position: (1, 44)
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
                    category: Identifier(Undefined("script_tag".to_owned())),
                    position: (1, 1)
                },
                Box::new(Parameter(vec![NamedParameter(
                    Token {
                        category: Identifier(Undefined("name".to_owned())),
                        position: (1, 12)
                    },
                    Box::new(Primitive(Token {
                        category: Number(2),
                        position: (1, 18)
                    }))
                )]))
            )
        );
    }

}
