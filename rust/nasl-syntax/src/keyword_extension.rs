use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::{End, Lexer},
    token::{Category, Keyword, Token},
    unclosed_statement, unclosed_token, unexpected_end, unexpected_statement, unexpected_token,
    variable_extension::CommaGroup,
    DeclareScope, Statement,
};

pub(crate) trait Keywords {
    /// Parses keywords.
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(End, Statement), SyntaxError>;
}

impl<'a> Lexer<'a> {
    fn parse_declaration(&mut self, scope: DeclareScope) -> Result<(End, Statement), SyntaxError> {
        let (end, params) = self.parse_comma_group(Category::Semicolon)?;
        if end == End::Continue {
            return Err(unexpected_end!("expected a finished statement."));
        }
        if let Some(errstmt) = params
            .iter()
            .find(|stmt| !matches!(stmt, Statement::Variable(_)))
        {
            return Err(unexpected_statement!(errstmt.clone()));
        }
        let result = Statement::Declare(scope, params);
        Ok((End::Done(Category::Semicolon), result))
    }
    fn parse_if(&mut self) -> Result<(End, Statement), SyntaxError> {
        let token = self.token().ok_or_else(|| unexpected_end!("if parsing"))?;
        let condition = match token.category() {
            Category::LeftParen => self.parse_paren(token),
            _ => Err(unexpected_token!(token)),
        }?
        .as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|cat| cat == Category::Semicolon)?;
        if end == End::Continue {
            return Err(unclosed_token!(token));
        }
        let r#else: Option<Statement> = {
            match self.peek() {
                Some(token) => match token.category() {
                    Category::Identifier(Some(Keyword::Else)) => {
                        self.token();
                        let (end, stmt) = self.statement(0, &|cat| cat == Category::Semicolon)?;
                        if end == End::Continue {
                            return Err(unexpected_statement!(stmt));
                        }
                        Some(stmt)
                    }
                    _ => {
                        None
                    }
                },
                None => None,
            }
        };
        Ok((
            End::Done(Category::Semicolon),
            Statement::If(Box::new(condition), Box::new(body), r#else.map(Box::new)),
        ))
    }

    fn jump_to_left_parenthesis(&mut self) -> Result<(), SyntaxError> {
        let token = self
            .token()
            .ok_or_else(|| unexpected_end!("expected paren."))?;
        if token.category() != Category::LeftParen {
            Err(unexpected_token!(token))
        } else {
            Ok(())
        }
    }

    fn parse_call_return_params(&mut self) -> Result<Statement, SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, parameter) = self.statement(0, &|cat| cat == Category::RightParen)?;
        let parameter = parameter.as_returnable_or_err()?;
        if end.is_done() {
            Ok(parameter)
        } else {
            Err(unexpected_end!("exit"))
        }
    }

    fn parse_exit(&mut self) -> Result<(End, Statement), SyntaxError> {
        let parameter = self.parse_call_return_params()?;
        let (_, should_be_semicolon) = self.statement(0, &|cat| cat == Category::Semicolon)?;
        if matches!(should_be_semicolon, Statement::NoOp(_)) {
            Ok((
                End::Done(Category::Semicolon),
                Statement::Exit(Box::new(parameter)),
            ))
        } else {
            Err(unexpected_statement!(should_be_semicolon))
        }
    }

    fn parse_include(&mut self) -> Result<(End, Statement), SyntaxError> {
        let parameter = self.parse_call_return_params()?;
        match parameter {
            Statement::Primitive(_) | Statement::Variable(_) | Statement::Array(_, _) => Ok((
                End::Done(Category::RightParen),
                Statement::Include(Box::new(parameter)),
            )),
            _ => Err(unexpected_statement!(parameter)),
        }
    }

    fn parse_function(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
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
        let (end, parameter) = self.parse_comma_group(Category::RightParen)?;
        if !end {
            return Err(unclosed_token!(token));
        }

        let block = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(block.category(), Category::LeftCurlyBracket) {
            return Err(unexpected_token!(block));
        }
        let block = self.parse_block(block)?;
        Ok((
            End::Done(Category::RightCurlyBracket),
            Statement::FunctionDeclaration(id, parameter, Box::new(block)),
        ))
    }

    fn parse_return(&mut self) -> Result<(End, Statement), SyntaxError> {
        let token = self.peek();
        if let Some(token) = token {
            if matches!(token.category(), Category::Semicolon) {
                self.token();
                return Ok((
                    End::Done(Category::Semicolon),
                    Statement::Return(Box::new(Statement::NoOp(Some(token)))),
                ));
            }
        }
        let (end, parameter) = self.statement(0, &|cat| cat == Category::Semicolon)?;
        let parameter = parameter.as_returnable_or_err()?;
        if let End::Done(cat) = end {
            Ok((
                End::Done(cat),
                Statement::Return(Box::new(parameter)),
            ))
        } else {
            Err(unexpected_end!("exit"))
        }
    }
    fn parse_for(&mut self) -> Result<(End, Statement), SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, assignment) = self.statement(0, &|c| c == Category::Semicolon)?;
        if !matches!(assignment, Statement::Assign(_, _, _, _)) {
            return Err(unexpected_statement!(assignment));
        }
        if end == End::Continue {
            return Err(unclosed_statement!(assignment));
        }
        // `for (i = 0; i < 10; i++) display("hi");`
        let (end, condition) = self.statement(0, &|c| c == Category::Semicolon)?;
        let condition = condition.as_returnable_or_err()?;
        if end == End::Continue {
            return Err(unclosed_statement!(condition));
        }
        let (end, update) = self.statement(0, &|c| c == Category::RightParen)?;
        if end == End::Continue {
            return Err(unclosed_statement!(update));
        }
        let (end, body) = self.statement(0, &|c| c == Category::Semicolon)?;
        match end {
            End::Done(cat) => Ok((
                End::Done(cat),
                Statement::For(
                    Box::new(assignment),
                    Box::new(condition),
                    Box::new(update),
                    Box::new(body),
                ),
            )),
            End::Continue => Err(unclosed_statement!(body)),
        }
    }

    fn parse_while(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, condition) = self.statement(0, &|c| c == Category::RightParen)?;
        if !end {
            return Err(unclosed_token!(token));
        }
        let condition = condition.as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|c| c == Category::Semicolon)?;
        if !end {
            return Err(unclosed_token!(token));
        }
        Ok((
            End::Done(Category::Semicolon),
            Statement::While(Box::new(condition), Box::new(body)),
        ))
    }
    fn parse_repeat(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        let (end, body) = self.statement(0, &|c| c == Category::Semicolon)?;

        if !end {
            return Err(unclosed_token!(token));
        }
        let until: Statement = {
            match self.token() {
                Some(token) => match token.category() {
                    Category::Identifier(Some(Keyword::Until)) => {
                        let (end, stmt) = self.statement(0, &|cat| cat == Category::Semicolon)?;
                        if !end {
                            return Err(unclosed_token!(token));
                        }
                        Ok(stmt)
                    }
                    _ => Err(unexpected_token!(token)),
                },
                None => Err(unexpected_end!("in repeat")),
            }?
            .as_returnable_or_err()?
        };
        Ok((
            End::Done(Category::Semicolon),
            Statement::Repeat(Box::new(body), Box::new(until)),
        ))
    }

    fn parse_foreach(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
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
        if !end {
            Err(unclosed_token!(token))
        } else {
            Ok((
                End::Done(Category::Semicolon),
                Statement::ForEach(variable, Box::new(r#in), Box::new(block)),
            ))
        }
    }
    fn parse_fct_anon_args(
        &mut self,
        keyword: Token,
    ) -> Result<(End, Statement), SyntaxError> {
        match self.peek() {
            Some(token) => match token.category() {
                Category::LeftBrace => {
                    self.token();
                    let (end, lookup) = self.statement(0, &|c| c == Category::RightBrace)?;
                    let lookup = lookup.as_returnable_or_err()?;
                    if end == End::Continue {
                        Err(unclosed_token!(token))
                    } else {

                        Ok((
                            End::Continue,
                            Statement::Array(keyword, Some(Box::new(lookup))),
                        ))
                    }
                }
                _ => {
                    Ok((End::Continue, Statement::Array(keyword, None)))
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
    ) -> Result<(End, Statement), SyntaxError> {
        match keyword {
            Keyword::For => self.parse_for(),
            Keyword::ForEach => self.parse_foreach(token),
            Keyword::If => self.parse_if(),
            Keyword::Else => Err(unexpected_token!(token)), // handled in if
            Keyword::While => self.parse_while(token),
            Keyword::Repeat => self.parse_repeat(token),
            Keyword::Until => Err(unexpected_token!(token)), // handled in repeat
            Keyword::LocalVar => self.parse_declaration(DeclareScope::Local),
            Keyword::GlobalVar => self.parse_declaration(DeclareScope::Global),
            Keyword::Null => Ok((End::Continue, Statement::Primitive(token))),
            Keyword::Return => self.parse_return(),
            Keyword::Include => self.parse_include(),
            Keyword::Exit => self.parse_exit(),
            Keyword::FCTAnonArgs => self.parse_fct_anon_args(token),
            Keyword::True => Ok((End::Continue, Statement::Primitive(token))),
            Keyword::False => Ok((End::Continue, Statement::Primitive(token))),
            Keyword::Function => self.parse_function(token),
            Keyword::ACT(category) => Ok((End::Continue, Statement::AttackCategory(category))),
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        parse,
        token::{Category, Keyword, StringCategory, Token},
        AssignOrder, DeclareScope, SyntaxError,
    };

    use crate::Statement::*;
    use crate::TokenCategory::*;

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
                    Box::new(Parameter(vec![Primitive(Token {
                        category: String(StringCategory::Quotable),
                        position: (29, 30)
                    })]))
                )),
                Some(Box::new(Call(
                    Token {
                        category: Identifier(None),
                        position: (39, 46)
                    },
                    Box::new(Parameter(vec![Primitive(Token {
                        category: String(StringCategory::Quotable),
                        position: (48, 50)
                    })]))
                )))
            )
        );
        parse("if( version[1] ) report += '\nVersion: ' + version[1];")
            .next()
            .unwrap()
            .unwrap();
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
        let expected = |scope: DeclareScope, offset: usize| {
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
            expected(DeclareScope::Local, 0)
        );
        assert_eq!(
            parse("global_var a, b, c;").next().unwrap().unwrap(),
            expected(DeclareScope::Global, 1)
        );
        Ok(())
    }

    #[test]
    fn null() {
        assert_eq!(
            parse("NULL;").next().unwrap().unwrap(),
            Primitive(Token {
                category: Identifier(Some(Keyword::Null)),
                position: (0, 4)
            })
        );
    }

    #[test]
    fn boolean() {
        assert_eq!(
            parse("TRUE;").next().unwrap().unwrap(),
            Primitive(Token {
                category: Identifier(Some(Keyword::True)),
                position: (0, 4)
            })
        );
        assert_eq!(
            parse("FALSE;").next().unwrap().unwrap(),
            Primitive(Token {
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
                    Exit(_),
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
                    Return(_),
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
            For(_, _, _, _)
        ))
    }

    #[test]
    fn while_loop() {
        let code = "while (TRUE) ;";
        assert!(matches!(parse(code).next().unwrap().unwrap(), While(_, _)))
    }

    #[test]
    fn repeat_loop() {
        let code = "repeat ; until 1 == 1;";
        assert!(matches!(parse(code).next().unwrap().unwrap(), Repeat(_, _)))
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
                    ForEach(_, _, _),
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
            Include(_)
        ))
    }

    #[test]
    fn function() {
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
                    category: Number(1),
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
                    category: Number(1),
                    position: (39, 40)
                })))]))
            )
        );
    }

    #[test]
    fn fct_anon_args() {
        assert_eq!(
            parse("arg1 = _FCT_ANON_ARGS[0];").next().unwrap(),
            Ok(Assign(
                Category::Equal,
                AssignOrder::AssignReturn,
                Box::new(Variable(Token {
                    category: Category::Identifier(None),
                    position: (0, 4)
                },)),
                Box::new(Array(
                    Token {
                        category: Category::Identifier(Some(Keyword::FCTAnonArgs)),
                        position: (7, 21),
                    },
                    Some(Box::new(Primitive(Token {
                        category: Category::Number(0),
                        position: (22, 23)
                    })))
                ))
            ))
        );
        assert_eq!(
            parse("arg1 = _FCT_ANON_ARGS;").next().unwrap(),
            Ok(Assign(
                Category::Equal,
                AssignOrder::AssignReturn,
                Box::new(Variable(Token {
                    category: Category::Identifier(None),
                    position: (0, 4)
                },)),
                Box::new(Array(
                    Token {
                        category: Category::Identifier(Some(Keyword::FCTAnonArgs)),
                        position: (7, 21),
                    },
                    None
                ))
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
