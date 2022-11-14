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
        let result = match self.statement(0, &|cat| cat == Category::Semicolon)? {
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
        match self.end_category {
            Some(Category::Semicolon) => Ok(result),
            _ => Err(unexpected_end!("parsing local_var")),
        }
    }
    fn parse_if(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        let token = self.token().ok_or_else(|| unexpected_end!("if parsing"))?;
        let condition = match token.category() {
            Category::LeftParen => self.parse_paren(token),
            _ => Err(unexpected_token!(token)),
        }?
        .as_returnable_or_err()?;
        let body = self.statement(0, &|cat| cat == Category::Semicolon)?;
        if !self
            .end_category
            .map(|ec| ec == Category::Semicolon || ec == Category::RightCurlyBracket)
            .unwrap_or(false)
        {
            return Err(unclosed_token!(token));
        }
        let r#else: Option<Statement> = {
            match self.tokenizer.next() {
                Some(token) => match token.category() {
                    Category::Identifier(Some(Keyword::Else)) => {
                        Some(self.statement(0, &|cat| cat == Category::Semicolon)?)
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
        let parameter = self
            .statement(0, &|cat| cat == Category::RightParen)?
            .as_returnable_or_err()?;
        if self.end_category.is_some() {
            Ok((PrefixState::Break, Statement::Exit(Box::new(parameter))))
        } else {
            Err(unexpected_end!("exit"))
        }
    }

    fn parse_return(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        let parameter = self
            .statement(0, &|cat| cat == Category::Semicolon)?
            .as_returnable_or_err()?;
        if self.end_category.is_some() {
            Ok((PrefixState::Break, Statement::Return(Box::new(parameter))))
        } else {
            Err(unexpected_end!("exit"))
        }
    }
    fn parse_for(&mut self) -> Result<(PrefixState, Statement), SyntaxError> {
        self.paren_base()?;
        let assignment = self.statement(0, &|c| c == Category::Semicolon)?;
        if !matches!(assignment, Statement::Assign(_, _, _, _)) {
            return Err(unexpected_statement!(assignment));
        }
        if self.end_category.is_none() {
            return Err(unclosed_statement!(assignment));
        }
        // `for (i = 0; i < 10; i++) display("hi");`
        let condition = self
            .statement(0, &|c| c == Category::Semicolon)?
            .as_returnable_or_err()?;
        let pre_body = self.statement(0, &|c| c == Category::RightParen)?;
        if self.end_category.is_none() {
            return Err(unclosed_statement!(pre_body));
        }
        let body = self.statement(0, &|c| c == Category::Semicolon)?;
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
}

impl<'a> Keywords for Lexer<'a> {
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(PrefixState, Statement), SyntaxError> {
        match keyword {
            Keyword::For => self.parse_for(),
            Keyword::ForEach => todo!(),
            Keyword::If => self.parse_if(),
            Keyword::Else => Err(unexpected_token!(token)), // handled in if
            Keyword::While => todo!(),
            Keyword::Repeat => todo!(),
            Keyword::Until => todo!(),
            Keyword::LocalVar => self.parse_declaration(DeclareScope::Local),
            Keyword::GlobalVar => self.parse_declaration(DeclareScope::Global),
            Keyword::Null => Ok((PrefixState::Continue, Statement::Primitive(token))),
            Keyword::Return => self.parse_return(),
            Keyword::Include => todo!(),
            Keyword::Exit => self.parse_exit(),
            Keyword::FCTAnonArgs => todo!(),
            Keyword::True => Ok((PrefixState::Continue, Statement::Primitive(token))),
            Keyword::False => Ok((PrefixState::Continue, Statement::Primitive(token))),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::{DeclareScope, Statement},
        parse,
        token::{Category, Keyword, StringCategory, Token},
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
                Box::new(Block(vec![NoOp(Some(Token {
                    category: Semicolon,
                    position: (19, 20)
                }))])),
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
