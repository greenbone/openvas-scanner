use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::Statement,
    lexer::{DeclareScope, Lexer},
    prefix_extension::PrefixState,
    token::{Category, Keyword, Token},
    unclosed_statement, unclosed_token, unexpected_end, unexpected_statement, unexpected_token,
};

pub(crate) trait Keywords {
    /// Parses keywords.
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(PrefixState, Statement), SyntaxError>;
}

impl<'a> Lexer<'a> {
    fn parse_declaration(
        &mut self,
        scope: DeclareScope,
    ) -> Result<(PrefixState, Statement), SyntaxError> {
        let (end, stmt) = self.statement(0, &|cat| cat == Category::Semicolon)?;
        if !end {
            return Err(unexpected_end!("expected a finished statement."));
        }
        let result = match stmt {
            Statement::Variable(var) => Ok((
                PrefixState::Break,
                Statement::Declare(scope, vec![Statement::Variable(var)]),
            )),
            Statement::Parameter(params) => {
                for p in params.clone() {
                    if let Statement::Variable(_) = p {
                        continue;
                    }
                    return Err(unexpected_statement!(p));
                }
                Ok((PrefixState::Break, Statement::Declare(scope, params)))
            }
            stmt => Err(unexpected_statement!(stmt)),
        }?;
        Ok(result)
    }
    fn parse_if(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        let token = self.token().ok_or_else(|| unexpected_end!("if parsing"))?;
        let condition = match token.category() {
            Category::LeftParen => self.parse_paren(token),
            _ => Err(unexpected_token!(token)),
        }?
        .as_returnable_or_err()?;
        self.unhandled_token = None;
        let (end, body) = self.statement(0, &|cat| cat == Category::Semicolon)?;
        if !end {
            return Err(unclosed_token!(token));
        }
        self.unhandled_token = None;
        let r#else: Option<Statement> = {
            match self.token() {
                Some(token) => match token.category() {
                    Category::Identifier(Some(Keyword::Else)) => {
                        let (end, stmt) = self.statement(0, &|cat| cat == Category::Semicolon)?;
                        if !end {
                            return Err(unexpected_statement!(stmt));
                        }
                        Some(stmt)
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

    fn paren_base(&mut self) -> Result<(), SyntaxError> {
        let token = self
            .token()
            .ok_or_else(|| unexpected_end!("expected paren."))?;
        if token.category() != Category::LeftParen {
            Err(unexpected_token!(token))
        } else {
            Ok(())
        }
    }

    fn parse_exit(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        self.paren_base()?;
        let (end, parameter) = self.statement(0, &|cat| cat == Category::RightParen)?;
        let parameter = parameter.as_returnable_or_err()?;
        if end {
            let (_, should_be_semicolon) = self.statement(0, &|cat| cat == Category::Semicolon)?;
            if matches!(should_be_semicolon, Statement::NoOp(_)) {
                Ok((PrefixState::Break, Statement::Exit(Box::new(parameter))))
            } else {
                Err(unexpected_statement!(should_be_semicolon))
            }
            // TODO parse to to ;
        } else {
            Err(unexpected_end!("exit"))
        }
    }

    fn parse_include(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        self.paren_base()?;
        let (end, parameter) = self.statement(0, &|cat| cat == Category::RightParen)?;
        let parameter = parameter.as_returnable_or_err()?;
        if end {
            match parameter {
                Statement::Primitive(_) | Statement::Variable(_) | Statement::Array(_, _) => {
                    // TODO parse to end!
                    Ok((PrefixState::Break, Statement::Include(Box::new(parameter))))
                }
                _ => Err(unexpected_statement!(parameter)),
            }
        } else {
            Err(unexpected_end!("exit"))
        }
    }

    fn parse_function(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        let id = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(id.category(), Category::Identifier(None)) {
            return Err(unexpected_token!(id));
        }
        let paren = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(paren.category(), Category::LeftParen) {
            return Err(unexpected_token!(paren));
        }
        let parameter = match self.parse_paren(id)? {
            Statement::Variable(x) => vec![Statement::Variable(x)],
            Statement::Parameter(x) => x,
            Statement::NoOp(_) => vec![],
            stmt => return Err(unexpected_statement!(stmt)),
        };
        let block = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(block.category(), Category::LeftCurlyBracket) {
            return Err(unexpected_token!(block));
        }
        let block = self.parse_block(block)?;
        Ok((
            PrefixState::Break,
            Statement::FunctionDeclaration(id, parameter, Box::new(block)),
        ))
    }

    fn parse_return(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        let (end, parameter) = self.statement(0, &|cat| cat == Category::Semicolon)?;
        let parameter = parameter.as_returnable_or_err()?;
        if end {
            // TODO parse to end
            Ok((PrefixState::Break, Statement::Return(Box::new(parameter))))
        } else {
            Err(unexpected_end!("exit"))
        }
    }
    fn parse_for(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        self.paren_base()?;
        let (end, assignment) = self.statement(0, &|c| c == Category::Semicolon)?;
        if !matches!(assignment, Statement::Assign(_, _, _, _)) {
            return Err(unexpected_statement!(assignment));
        }
        if !end {
            return Err(unclosed_statement!(assignment));
        }
        // `for (i = 0; i < 10; i++) display("hi");`
        let (end, condition) = self.statement(0, &|c| c == Category::Semicolon)?;
        let condition = condition.as_returnable_or_err()?;
        if !end {
            return Err(unclosed_statement!(condition));
        }
        let (end, pre_body) = self.statement(0, &|c| c == Category::RightParen)?;
        if !end {
            return Err(unclosed_statement!(pre_body));
        }
        let (end, body) = self.statement(0, &|c| c == Category::Semicolon)?;
        if !end {
            return Err(unclosed_statement!(body));
        }
        Ok((
            PrefixState::Break,
            Statement::For(
                Box::new(assignment),
                Box::new(condition),
                Box::new(pre_body),
                Box::new(body),
            ),
        ))
    }

    fn parse_while(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        self.paren_base()?;
        let (end, condition) = self.statement(0, &|c| c == Category::RightParen)?;
        let condition = condition.as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|c| c == Category::Semicolon)?;
        Ok((
            PrefixState::Break,
            Statement::While(Box::new(condition), Box::new(body)),
        ))
    }
    fn parse_repeat(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        let (end, body) = self.statement(0, &|c| c == Category::Semicolon)?;

        let until: Statement = {
            match self.token() {
                Some(token) => match token.category() {
                    Category::Identifier(Some(Keyword::Until)) => {
                        let (end, stmt) = self.statement(0, &|cat| cat == Category::Semicolon)?;
                        Ok(stmt)
                    }
                    _ => Err(unexpected_token!(token)),
                },
                None => Err(unexpected_end!("in repeat")),
            }?
            .as_returnable_or_err()?
        };
        Ok((
            PrefixState::Break,
            Statement::Repeat(Box::new(body), Box::new(until)),
        ))
    }

    fn parse_foreach(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        let variable: Token = {
            match self.token() {
                Some(token) => match token.category() {
                    Category::Identifier(None) => Ok(token),
                    _ => Err(unexpected_token!(token)),
                },
                None => Err(unexpected_end!("in foreach")),
            }?
        };
        let r#in: Statement = {
            let token = self.token().ok_or_else(|| unexpected_end!("in foreach"))?;
            match token.category() {
                Category::LeftParen => self.parse_paren(token),
                _ => Err(unexpected_token!(token)),
            }?
        };
        let (end, block) = self.statement(0, &|cat| cat == Category::Semicolon)?;
        Ok((
            PrefixState::Break,
            Statement::ForEach(variable, Box::new(r#in), Box::new(block)),
        ))
    }
    fn parse_fct_anon_args(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        match self.token() {
            Some(token) => match token.category() {
                Category::LeftBrace => {
                    let (end, lookup) = self.statement(0, &|c| c == Category::RightBrace)?;
                    let lookup = lookup.as_returnable_or_err()?;
                    if !end {
                        Err(unclosed_token!(token))
                    } else {
                        self.unhandled_token = None;
                        Ok((
                            PrefixState::Continue,
                            Statement::FCTAnonArgs(Some(Box::new(lookup))),
                        ))
                    }
                }
                _ => {
                    self.unhandled_token = Some(token);
                    Ok((PrefixState::Continue, Statement::FCTAnonArgs(None)))
                }
            },
            None => Err(unexpected_end!("in fct_anon_args")),
        }
    }
}

impl<'a> Keywords for Lexer<'a> {
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(PrefixState, Statement), SyntaxError> {
        match keyword {
            Keyword::For => self.parse_for(),
            Keyword::ForEach => self.parse_foreach(),
            Keyword::If => self.parse_if(),
            Keyword::Else => Err(unexpected_token!(token)), // handled in if
            Keyword::While => self.parse_while(),
            Keyword::Repeat => self.parse_repeat(),
            Keyword::Until => Err(unexpected_token!(token)), // handled in repeat
            Keyword::LocalVar => self.parse_declaration(DeclareScope::Local),
            Keyword::GlobalVar => self.parse_declaration(DeclareScope::Global),
            Keyword::Null => Ok((PrefixState::Continue, Statement::Primitive(token))),
            Keyword::Return => self.parse_return(),
            Keyword::Include => self.parse_include(),
            Keyword::Exit => self.parse_exit(),
            Keyword::FCTAnonArgs => self.parse_fct_anon_args(),
            Keyword::True => Ok((PrefixState::Continue, Statement::Primitive(token))),
            Keyword::False => Ok((PrefixState::Continue, Statement::Primitive(token))),
            Keyword::Function => self.parse_function(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::{AssignOrder, DeclareScope, Statement},
        parse,
        token::{Base, Category, Keyword, StringCategory, Token},
        SyntaxError,
    };

    use Category::*;
    use Statement::*;

    #[test]
    fn if_statement() {
        let actual = parse("if (description) script_oid('1'); else display('hi');")
            .next()
            .unwrap()
            .unwrap();
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
                Some(Box::new(Call(
                    Token {
                        category: Identifier(None),
                        position: (39, 46)
                    },
                    Box::new(Primitive(Token {
                        category: String(StringCategory::Quoteable),
                        position: (48, 50)
                    }))
                )))
            )
        );
        parse("if( version[1] ) report += '\nVersion: ' + version[1];").next().unwrap().unwrap();
    }

    #[test]
    fn if_block() {
        let actual = parse("if (description) { ; }").next().unwrap().unwrap();
        assert_eq!(
            actual,
            If(
                Box::new(Variable(Token {
                    category: Identifier(None),
                    position: (4, 15)
                })),
                Box::new(Block(vec![])),
                None
            )
        );
    }

    #[test]
    fn local_var() -> Result<(), SyntaxError> {
        let exspected = |scope: DeclareScope, offset: usize| {
            Declare(
                scope,
                vec![
                    Variable(Token {
                        category: Identifier(None),
                        position: (10 + offset, 11 + offset),
                    }),
                    Variable(Token {
                        category: Identifier(None),
                        position: (13 + offset, 14 + offset),
                    }),
                    Variable(Token {
                        category: Identifier(None),
                        position: (16 + offset, 17 + offset),
                    }),
                ],
            )
        };
        assert_eq!(
            parse("local_var a, b, c;").next().unwrap().unwrap(),
            exspected(DeclareScope::Local, 0)
        );
        assert_eq!(
            parse("global_var a, b, c;").next().unwrap().unwrap(),
            exspected(DeclareScope::Global, 1)
        );
        Ok(())
    }

    #[test]
    fn null() {
        assert_eq!(
            parse("NULL;").next().unwrap().unwrap(),
            Statement::Primitive(Token {
                category: Identifier(Some(Keyword::Null)),
                position: (0, 4)
            })
        );
    }

    #[test]
    fn boolean() {
        assert_eq!(
            parse("TRUE;").next().unwrap().unwrap(),
            Statement::Primitive(Token {
                category: Identifier(Some(Keyword::True)),
                position: (0, 4)
            })
        );
        assert_eq!(
            parse("FALSE;").next().unwrap().unwrap(),
            Statement::Primitive(Token {
                category: Identifier(Some(Keyword::False)),
                position: (0, 5)
            })
        );
    }
    #[test]
    fn exit() {
        let test_cases = [
            "exit(1)",
            "exit(a)",
            "exit(a(b))",
            "exit(23 + 5)",
            "exit((4 * 5))",
        ];
        for call in test_cases {
            assert!(
                matches!(
                    parse(&format!("{};", call)).next().unwrap().unwrap(),
                    Statement::Exit(_),
                ),
                "{}",
                call
            );
        }
    }

    #[test]
    fn r#return() {
        let test_cases = [
            "return 1",
            "return a",
            "return a(b)",
            "return 23 + 5",
            "return (4 * 5)",
        ];
        for call in test_cases {
            assert!(
                matches!(
                    parse(&format!("{};", call)).next().unwrap().unwrap(),
                    Statement::Return(_),
                ),
                "{}",
                call
            );
        }
    }

    #[test]
    fn for_loop() {
        let code = "for (i = 0; i < 10; i++) display('hi');";
        assert!(matches!(
            parse(code).next().unwrap().unwrap(),
            Statement::For(_, _, _, _)
        ))
    }

    #[test]
    fn while_loop() {
        let code = "while (TRUE) ;";
        assert!(matches!(
            parse(code).next().unwrap().unwrap(),
            Statement::While(_, _)
        ))
    }

    #[test]
    fn repeat_loop() {
        let code = "repeat ; until 1 == 1";
        assert!(matches!(
            parse(code).next().unwrap().unwrap(),
            Statement::Repeat(_, _)
        ))
    }

    #[test]
    fn foreach() {
        let test_cases = [
            "foreach info(list) { display(info); }",
            "foreach info( make_list('a', 'b')) { display(info); }",
        ];
        for call in test_cases {
            assert!(
                matches!(
                    parse(&format!("{};", call)).next().unwrap().unwrap(),
                    Statement::ForEach(_, _, _),
                ),
                "{}",
                call
            );
        }
    }

    #[test]
    fn include() {
        assert!(matches!(
            parse("include('test.inc');").next().unwrap().unwrap(),
            Statement::Include(_)
        ))
    }

    #[test]
    fn function() {
        use Statement::*;
        assert_eq!(
            parse("function register_packages( buf ) { return 1; }")
                .next()
                .unwrap()
                .unwrap(),
            FunctionDeclaration(
                Token {
                    category: Identifier(None),
                    position: (9, 26)
                },
                vec![Variable(Token {
                    category: Identifier(None),
                    position: (28, 31)
                })],
                Box::new(Block(vec![Return(Box::new(Primitive(Token {
                    category: Number(Base::Base10),
                    position: (43, 44)
                })))]))
            )
        );
        assert_eq!(
            parse("function register_packages( ) { return 1; }")
                .next()
                .unwrap()
                .unwrap(),
            FunctionDeclaration(
                Token {
                    category: Identifier(None),
                    position: (9, 26)
                },
                vec![],
                Box::new(Block(vec![Return(Box::new(Primitive(Token {
                    category: Number(Base::Base10),
                    position: (39, 40)
                })))]))
            )
        );
    }

    #[test]
    fn fct_anon_args() {
        assert_eq!(
            parse("arg1 = _FCT_ANON_ARGS[0];").next().unwrap(),
            Ok(Statement::Assign(
                Category::Equal,
                AssignOrder::Assign,
                Box::new(Variable(Token {
                    category: Category::Identifier(None),
                    position: (0, 4)
                },)),
                Box::new(Statement::FCTAnonArgs(Some(Box::new(
                    Statement::Primitive(Token {
                        category: Category::Number(Base::Base10),
                        position: (22, 23)
                    })
                ))))
            ))
        );
        assert_eq!(
            parse("arg1 = _FCT_ANON_ARGS;").next().unwrap(),
            Ok(Statement::Assign(
                Category::Equal,
                AssignOrder::Assign,
                Box::new(Variable(Token {
                    category: Category::Identifier(None),
                    position: (0, 4)
                },)),
                Box::new(Statement::FCTAnonArgs(None))
            ))
        );
    }

    #[test]
    fn unclosed() {
        assert!(parse("local_var a, b, c").next().unwrap().is_err());
        assert!(parse("local_var a, 1, c;").next().unwrap().is_err());
        assert!(parse("local_var 1;").next().unwrap().is_err());
        assert!(parse("if (description) { ; ").next().unwrap().is_err());
        assert!(parse("if (description) display(1)")
            .next()
            .unwrap()
            .is_err());
    }
}
