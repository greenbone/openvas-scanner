use crate::{
    error::SyntaxError,
    lexer::Statement,
    lexer::{End, Lexer},
    prefix_extension::PrefixState,
    token::{Category, Token},
    unclosed_token, unexpected_token,
};

pub(crate) trait Variables {
    /// Parses variables, function calls.
    fn parse_variable(&mut self, token: Token) -> Result<(PrefixState, Statement), SyntaxError>;
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
        while let Some(token) = self.token() {
            if token.category() == category {
                end = End::Done(category);
                break;
            }
            self.unhandled_token = Some(token);
            let (stmtend, param) = self.statement(0, &|c| c == category || c == Category::Comma)?;
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
    fn parse_variable(&mut self, token: Token) -> Result<(PrefixState, Statement), SyntaxError> {
        if token.category() != Category::Identifier(None) {
            return Err(unexpected_token!(token));
        }
        use PrefixState::*;

        if let Some(nt) = self.token() {
            match nt.category() {
                Category::LeftParen => {
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
                    let (end, lookup) = self.statement(0, &|c| c == Category::RightBrace)?;
                    let lookup = lookup.as_returnable_or_err()?;
                    if end == End::Continue {
                        return Err(unclosed_token!(token));
                    } else {
                        self.unhandled_token = None;
                        return Ok((Continue, Statement::Array(token, Some(Box::new(lookup)))));
                    }
                }
                _ => self.unhandled_token = Some(nt),
            }
        }
        Ok((Continue, Statement::Variable(token)))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::{AssignOrder, Statement},
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
        assert_eq!(result("a;"), Variable(token(Identifier(None), 0, 1)));
    }

    #[test]
    fn arrays() {
        assert_eq!(
            result("a[0];"),
            Array(
                token(Identifier(None), 0, 1),
                Some(Box::new(Primitive(token(Number(Base10), 2, 3))))
            )
        );

        assert_eq!(
            result("a = [1, 2, 3];"),
            Assign(
                Equal,
                AssignOrder::AssignReturn,
                Box::new(Array(
                    Token {
                        category: Identifier(None),
                        position: (0, 1)
                    },
                    None
                )),
                Box::new(Parameter(vec![
                    Primitive(Token {
                        category: Number(Base10),
                        position: (5, 6)
                    }),
                    Primitive(Token {
                        category: Number(Base10),
                        position: (8, 9)
                    }),
                    Primitive(Token {
                        category: Number(Base10),
                        position: (11, 12)
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
                        category: Identifier(None),
                        position: (0, 1)
                    },
                    Some(Box::new(Primitive(Token {
                        category: Number(Base10),
                        position: (2, 3)
                    })))
                )),
                Box::new(Parameter(vec![
                    Primitive(Token {
                        category: Number(Base10),
                        position: (8, 9)
                    }),
                    Primitive(Token {
                        category: Number(Base10),
                        position: (11, 12)
                    }),
                    Primitive(Token {
                        category: Number(Base10),
                        position: (14, 15)
                    })
                ]))
            )
        );
    }

    #[test]
    fn anon_function_call() {
        let fn_name = token(Identifier(None), 0, 1);
        let args = Box::new(Parameter(vec![
            Primitive(token(Number(Base10), 2, 3)),
            Primitive(token(Number(Base10), 5, 6)),
            Primitive(token(Number(Base10), 8, 9)),
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
                Box::new(Parameter(vec![NamedParameter(
                    Token {
                        category: Identifier(None),
                        position: (11, 15)
                    },
                    Box::new(Primitive(Token {
                        category: Number(Base10),
                        position: (17, 18)
                    }))
                )]))
            )
        );
    }

}
