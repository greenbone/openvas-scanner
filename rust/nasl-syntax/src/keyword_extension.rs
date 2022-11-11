use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::Statement,
    lexer::{DeclareScope, Lexer},
    prefix_extension::PrefixState,
    token::{Category, Keyword, Token},
    unclosed_token, unexpected_end, unexpected_statement, unexpected_token,
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
        }?;
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
}

impl<'a> Keywords for Lexer<'a> {
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(PrefixState, Statement), SyntaxError> {
        match keyword {
            Keyword::For => todo!(),
            Keyword::ForEach => todo!(),
            Keyword::If => self.parse_if(),
            Keyword::Else => Err(unexpected_token!(token)), // handled in if
            Keyword::While => todo!(),
            Keyword::Repeat => todo!(),
            Keyword::Until => todo!(),
            Keyword::LocalVar => self.parse_declaration(DeclareScope::Local),
            Keyword::GlobalVar => self.parse_declaration(DeclareScope::Global),
            Keyword::Null => todo!(),
            Keyword::Return => todo!(),
            Keyword::Include => todo!(),
            Keyword::Exit => todo!(),
            Keyword::FCTAnonArgs => todo!(),
            Keyword::True => todo!(),
            Keyword::False => todo!(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        lexer::{DeclareScope, Statement},
        token::{Category, StringCategory, Token},
        SyntaxError,
    };

    use Category::*;
    use Statement::*;

    #[test]
    fn if_statement() {
        let actual = crate::parse("if (description) script_oid('1'); else display('hi');")
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
        let actual = crate::parse("if (description) { ; }")
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
            crate::parse("local_var a, b, c;").next().unwrap().unwrap(),
            exspected(DeclareScope::Local, 0)
        );
        assert_eq!(
            crate::parse("global_var a, b, c;").next().unwrap().unwrap(),
            exspected(DeclareScope::Global, 1)
        );
        Ok(())
    }

    #[test]
    fn unclosed() {
        assert!(crate::parse("local_var a, b, c").next().unwrap().is_err());
        assert!(crate::parse("local_var a, 1, c;").next().unwrap().is_err());
        assert!(crate::parse("local_var 1;").next().unwrap().is_err());
        assert!(crate::parse("if (description) { ; ")
            .next()
            .unwrap()
            .is_err());
        assert!(crate::parse("if (description) display(1)")
            .next()
            .unwrap()
            .is_err());
    }
}
