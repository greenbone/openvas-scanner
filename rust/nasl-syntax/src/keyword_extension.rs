// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::{End, Lexer},
    token::{Category, IdentifierType, Token},
    unclosed_statement, unclosed_token, unexpected_end, unexpected_statement, unexpected_token,
    Statement, StatementKind,
};

pub(crate) trait Keywords {
    /// Parses keywords.
    fn parse_keyword(
        &mut self,
        keyword: IdentifierType,
        token: Token,
    ) -> Result<(End, Statement), SyntaxError>;
}

impl<'a> Lexer<'a> {
    fn parse_declaration(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, params) = self.parse_comma_group(Category::Semicolon)?;
        match end {
            End::Done(end) => {
                if let Some(errstmt) = params
                    .iter()
                    .find(|stmt| !matches!(stmt.kind(), StatementKind::Variable))
                {
                    return Err(unexpected_statement!(errstmt.clone()));
                }
                let result =
                    Statement::with_start_end_token(token, end, StatementKind::Declare(params));
                Ok(result)
            }
            End::Continue => Err(unexpected_end!("expected a finished statement.")),
        }
    }
    fn parse_if(&mut self, kw: Token) -> Result<Statement, SyntaxError> {
        let ptoken = self.token().ok_or_else(|| unexpected_end!("if parsing"))?;
        let condition = match ptoken.category() {
            Category::LeftParen => self.parse_paren(ptoken.clone())?,
            _ => return Err(unexpected_token!(ptoken.clone())),
        }
        .as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
        let end = {
            match end {
                End::Done(end) => end,
                End::Continue => return Err(unclosed_token!(ptoken)),
            }
        };

        let (ekw, r#else, end) = {
            match self.peek() {
                Some(token) => match token.category() {
                    Category::Identifier(IdentifierType::Else) => {
                        self.token();
                        let (end, stmt) = self.statement(0, &|cat| cat == &Category::Semicolon)?;

                        match end {
                            End::Done(end) => (Some(token), Some(stmt), end),
                            End::Continue => return Err(unexpected_statement!(stmt)),
                        }
                    }
                    _ => (None, None, end),
                },
                None => (None, None, end),
            }
        };
        let result = Statement::with_start_end_token(
            kw,
            end.clone(),
            StatementKind::If(
                Box::new(condition),
                Box::new(body),
                ekw,
                r#else.map(Box::new),
            ),
        );
        Ok(result)
    }

    fn jump_to_left_parenthesis(&mut self) -> Result<(), SyntaxError> {
        let token = self
            .token()
            .ok_or_else(|| unexpected_end!("expected paren."))?;
        if token.category() != &Category::LeftParen {
            Err(unexpected_token!(token))
        } else {
            Ok(())
        }
    }

    fn parse_call_return_params(&mut self) -> Result<Statement, SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, parameter) = self.statement(0, &|cat| cat == &Category::RightParen)?;
        let parameter = parameter.as_returnable_or_err()?;
        match end {
            End::Done(_) => Ok(parameter),
            End::Continue => Err(unexpected_end!("exit")),
        }
    }

    fn parse_exit(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        // TODO maybe refactor to reuse function call and hindsight verification
        let parameter = self.parse_call_return_params()?;
        let (_, should_be_semicolon) = self.statement(0, &|cat| cat == &Category::Semicolon)?;

        if !matches!(should_be_semicolon.kind(), &StatementKind::NoOp) {
            // exit must be followed by ; nothing else
            return Err(unexpected_statement!(should_be_semicolon));
        }

        Ok(Statement::with_start_end_token(
            token,
            should_be_semicolon.end().clone(),
            StatementKind::Exit(Box::new(parameter)),
        ))
    }

    fn parse_include(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        // TODO maybe refactor to reuse function call and hindsight verification
        let parameter = self.parse_call_return_params()?;
        let (_, should_be_semicolon) = self.statement(0, &|cat| cat == &Category::Semicolon)?;

        if !matches!(should_be_semicolon.kind(), &StatementKind::NoOp) {
            // exit must be followed by ; nothing else
            return Err(unexpected_statement!(should_be_semicolon));
        }
        Ok(Statement::with_start_end_token(
            token,
            should_be_semicolon.end().clone(),
            StatementKind::Include(Box::new(parameter)),
        ))
    }

    fn parse_function(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let id = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(
            id.category(),
            Category::Identifier(IdentifierType::Undefined(_))
        ) {
            return Err(unexpected_token!(id));
        }
        let paren = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(paren.category(), Category::LeftParen) {
            return Err(unexpected_token!(paren));
        }
        let (gend, parameter) = self.parse_comma_group(Category::RightParen)?;
        let parameter_end_token = match gend {
            End::Done(t) => t,
            End::Continue => return Err(unclosed_token!(token)),
        };
        let parameter = Statement::with_start_end_token(
            paren,
            parameter_end_token,
            StatementKind::Parameter(parameter),
        );

        let block = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(block.category(), Category::LeftCurlyBracket) {
            return Err(unexpected_token!(block));
        }
        let block = self.parse_block(block)?;
        Ok(Statement::with_start_end_token(
            token,
            block.end().clone(),
            StatementKind::FunctionDeclaration(id, Box::new(parameter), Box::new(block)),
        ))
    }

    fn parse_return(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        if let Some(sc) = self.peek() {
            if matches!(sc.category(), Category::Semicolon) {
                self.token();
                return Ok(Statement::with_start_end_token(
                    token,
                    sc.clone(),
                    StatementKind::Return(Box::new(Statement::without_token(StatementKind::NoOp))),
                ));
            }
        }
        let (end, parameter) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
        let parameter = parameter.as_returnable_or_err()?;
        match end {
            End::Done(end) => Ok(Statement::with_start_end_token(
                token,
                end,
                StatementKind::Return(Box::new(parameter)),
            )),
            End::Continue => Err(unclosed_statement!(parameter)),
        }
    }
    fn parse_continue(&mut self, kw: Token) -> Result<Statement, SyntaxError> {
        let token = self.peek();
        if let Some(token) = token {
            if matches!(token.category(), Category::Semicolon) {
                self.token();
                return Ok(Statement::with_start_end_token(
                    kw,
                    token,
                    StatementKind::Continue,
                ));
            } else {
                return Err(unexpected_token!(token));
            }
        }
        Err(unexpected_end!("exit"))
    }
    fn parse_break(&mut self, kw: Token) -> Result<Statement, SyntaxError> {
        let token = self.peek();
        if let Some(token) = token {
            if matches!(token.category(), Category::Semicolon) {
                self.token();
                return Ok(Statement::with_start_end_token(
                    kw,
                    token,
                    StatementKind::Break,
                ));
            } else {
                return Err(unexpected_token!(token));
            }
        }
        Err(unexpected_end!("exit"))
    }

    fn map_syntax_error_to_unclosed_left_paren(e: SyntaxError) -> SyntaxError {
        match e.kind() {
            crate::ErrorKind::UnexpectedToken(k) => unclosed_token!(Token {
                category: Category::LeftParen,
                line_column: k.line_column,
                position: k.position,
            }),
            _ => e,
        }
    }

    fn is_end_of_category(end: &End, category: Category) -> bool {
        match end {
            End::Done(x) => x.category() == &category,
            End::Continue => false,
        }
    }

    fn parse_for(&mut self, kw: Token) -> Result<Statement, SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, assignment) = self.statement(0, &|c| c == &Category::Semicolon)?;
        if !matches!(
            assignment.kind(),
            StatementKind::Assign(..) | StatementKind::NoOp
        ) {
            return Err(unexpected_statement!(assignment));
        }
        if end == End::Continue {
            return Err(unclosed_statement!(assignment));
        }
        // `for (i = 0; i < 10; i++) display("hi");`
        let (end, condition) = self.statement(0, &|c| c == &Category::Semicolon)?;
        let condition = condition.as_returnable_or_err()?;
        if end == End::Continue {
            return Err(unclosed_statement!(condition));
        }
        let (end, update) = match self.peek() {
            // no update statement provided
            Some(Token {
                category: Category::RightParen,
                line_column,
                position,
            }) => {
                self.token();
                (
                    End::Done(Token {
                        category: Category::RightParen,
                        line_column,
                        position,
                    }),
                    Statement::without_token(StatementKind::NoOp),
                )
            }
            _ => self
                .statement(0, &|c| c == &Category::RightParen)
                .map_err(Self::map_syntax_error_to_unclosed_left_paren)?,
        };
        if !Self::is_end_of_category(&end, Category::RightParen) {
            let ut = update.as_token();
            return Err(unclosed_token!(Token {
                category: Category::LeftParen,
                line_column: ut.line_column,
                position: ut.position
            }));
        }
        let (end, body) = self.statement(0, &|c| c == &Category::Semicolon)?;
        match end {
            End::Continue => Err(unclosed_statement!(body)),
            End::Done(end) => Ok(Statement::with_start_end_token(
                kw,
                end.clone(),
                StatementKind::For(
                    Box::new(assignment),
                    Box::new(condition),
                    Box::new(update),
                    Box::new(body),
                ),
            )),
        }
    }

    fn parse_while(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, condition) = self
            .statement(0, &|c| c == &Category::RightParen)
            .map_err(Self::map_syntax_error_to_unclosed_left_paren)?;
        let ct = condition.as_token();
        if !Self::is_end_of_category(&end, Category::RightParen) {
            return Err(unclosed_token!(Token {
                category: Category::LeftParen,
                line_column: ct.line_column,
                position: ct.position,
            }));
        }
        let condition = condition.as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|c| c == &Category::Semicolon)?;
        match end {
            End::Done(end) => Ok(Statement::with_start_end_token(
                token,
                end.clone(),
                StatementKind::While(Box::new(condition), Box::new(body)),
            )),
            End::Continue => Err(unclosed_token!(token)),
        }
    }
    fn parse_repeat(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, body) = self.statement(0, &|c| c == &Category::Semicolon)?;

        if !end {
            return Err(unclosed_token!(token));
        }
        let (until, end) = {
            match self.token() {
                Some(token) => match token.category() {
                    Category::Identifier(IdentifierType::Until) => {
                        let (end, stmt) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
                        match end {
                            End::Done(end) => Ok((stmt, end)),
                            End::Continue => return Err(unclosed_token!(token)),
                        }
                    }
                    _ => Err(unexpected_token!(token)),
                },
                None => Err(unexpected_end!("in repeat")),
            }?
        };
        let until = until.as_returnable_or_err()?;
        Ok(Statement::with_start_end_token(
            token,
            end.clone(),
            StatementKind::Repeat(Box::new(body), Box::new(until)),
        ))
    }

    fn parse_foreach(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let variable: Token = {
            match self.token() {
                Some(token) => match token.category() {
                    Category::Identifier(IdentifierType::Undefined(_)) => Ok(token),
                    _ => Err(unexpected_token!(token)),
                },
                None => Err(unexpected_end!("in foreach")),
            }?
        };
        let r#in: Statement = {
            let token = self.token().ok_or_else(|| unexpected_end!("in foreach"))?;
            match token.category() {
                Category::LeftParen => self
                    .parse_paren(token.clone())
                    .map_err(|_| unclosed_token!(token)),
                _ => Err(unexpected_token!(token)),
            }?
        };
        let (end, block) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
        match end {
            End::Done(end) => Ok(Statement::with_start_end_token(
                token,
                end,
                StatementKind::ForEach(variable, Box::new(r#in), Box::new(block)),
            )),

            End::Continue => Err(unclosed_token!(token)),
        }
    }
    fn parse_fct_anon_args(&mut self, keyword: Token) -> Result<Statement, SyntaxError> {
        match self.peek() {
            Some(token) => match token.category() {
                Category::LeftBrace => {
                    self.token();
                    let (end, lookup) = self.statement(0, &|c| c == &Category::RightBrace)?;
                    let lookup = lookup.as_returnable_or_err()?;
                    match end {
                        End::Done(end) => Ok(Statement::with_start_end_token(
                            keyword,
                            end,
                            StatementKind::Array(Some(Box::new(lookup))),
                        )),
                        End::Continue => Err(unclosed_token!(token)),
                    }
                }
                _ => Ok(Statement::with_start_token(
                    keyword,
                    StatementKind::Array(None),
                )),
            },
            None => Err(unexpected_end!("in fct_anon_args")),
        }
    }
}

impl<'a> Keywords for Lexer<'a> {
    fn parse_keyword(
        &mut self,
        keyword: IdentifierType,
        token: Token,
    ) -> Result<(End, Statement), SyntaxError> {
        match keyword {
            IdentifierType::For => self
                .parse_for(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::ForEach => self
                .parse_foreach(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::If => self
                .parse_if(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Else => Err(unexpected_token!(token)), // handled in if
            IdentifierType::While => self
                .parse_while(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Repeat => self
                .parse_repeat(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Until => Err(unexpected_token!(token)), // handled in repeat
            IdentifierType::LocalVar | IdentifierType::GlobalVar => self
                .parse_declaration(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Return => self
                .parse_return(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Include => self
                .parse_include(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Exit => self
                .parse_exit(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::FCTAnonArgs => self
                .parse_fct_anon_args(token)
                .map(|stmt| (End::Continue, stmt)),
            IdentifierType::Null | IdentifierType::True | IdentifierType::False => Ok((
                End::Continue,
                Statement::with_start_token(token, StatementKind::Primitive),
            )),
            IdentifierType::ACT(_) => Ok((
                End::Continue,
                Statement::with_start_token(token, StatementKind::AttackCategory),
            )),
            IdentifierType::Function => self
                .parse_function(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Continue => self
                .parse_continue(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),

            IdentifierType::Break => self
                .parse_break(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            IdentifierType::Undefined(_) => Err(unexpected_token!(token)),
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        parse,
        token::{Category, IdentifierType},
        Statement,
    };

    use crate::StatementKind::*;
    use crate::TokenCategory::*;

    #[test]
    fn if_statement() {
        let actual = parse("if (description) script_oid('1'); else display('hi');")
            .next()
            .unwrap()
            .unwrap();
        match actual.kind() {
            If(_, _, Some(_), Some(_)) => {}
            _ => unreachable!("{actual} must be if with else stmt."),
        }

        let actual = parse("if( version[1] ) report += '\nVersion: ' + version[1];")
            .next()
            .unwrap()
            .unwrap();
        match actual.kind() {
            If(_, _, None, None) => {}
            _ => unreachable!("{actual} must be if without else stmt."),
        }
    }

    #[test]
    fn if_block() {
        let actual = parse("if (description) { ; }").next().unwrap().unwrap();
        match actual.kind() {
            If(_, b, _, _) => match b.kind() {
                Block(v) => {
                    assert_eq!(v, &vec![]);
                }
                _ => unreachable!("{b} must be a block stmt."),
            },
            _ => unreachable!("{actual} must be an if stmt."),
        }
    }

    #[test]
    fn local_var() {
        let expected = |actual: Statement, scope: Category| match actual.kind() {
            Declare(vars) => {
                assert_eq!(actual.as_token().category(), &scope);
                assert_eq!(vars.len(), 3);
            }
            _ => unreachable!("{actual} must be an declare stmt."),
        };
        expected(
            parse("local_var a, b, c;").next().unwrap().unwrap(),
            Category::Identifier(IdentifierType::LocalVar),
        );
        expected(
            parse("global_var a, b, c;").next().unwrap().unwrap(),
            Category::Identifier(IdentifierType::GlobalVar),
        );
    }

    #[test]
    fn null() {
        let result = parse("NULL;").next().unwrap().unwrap();
        assert_eq!(result.kind(), &Primitive);
        assert_eq!(
            result.as_token().category(),
            &Identifier(IdentifierType::Null)
        );
    }

    #[test]
    fn boolean() {
        let result = parse("TRUE;").next().unwrap().unwrap();
        assert_eq!(result.kind(), &Primitive);
        assert_eq!(
            result.as_token().category(),
            &Identifier(IdentifierType::True)
        );
        let result = parse("FALSE;").next().unwrap().unwrap();
        assert_eq!(result.kind(), &Primitive);
        assert_eq!(
            result.as_token().category(),
            &Identifier(IdentifierType::False)
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
            let result = parse(&format!("{call};")).next().unwrap().unwrap();
            assert!(matches!(result.kind(), &Exit(..),), "{}", call);
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
            let result = parse(&format!("{call};")).next().unwrap().unwrap();
            assert!(matches!(result.kind(), &Return(..),), "{}", call);
        }
    }

    #[test]
    fn for_loop() {
        let code = "for (i = 0; i < 10; i++) display('hi');";
        assert!(matches!(
            parse(code).next().unwrap().unwrap().kind(),
            &For(..)
        ));
        let code = "for (i = 0; i < 10; ) i = 10;";
        assert!(matches!(
            parse(code).next().unwrap().unwrap().kind(),
            &For(..)
        ))
    }

    #[test]
    fn while_loop() {
        let code = "while (TRUE) ;";
        assert!(matches!(
            parse(code).next().unwrap().unwrap().kind(),
            &While(..)
        ))
    }

    #[test]
    fn repeat_loop() {
        let code = "repeat ; until 1 == 1;";
        assert!(matches!(
            parse(code).next().unwrap().unwrap().kind(),
            &Repeat(..)
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
                    parse(&format!("{call};")).next().unwrap().unwrap().kind(),
                    &ForEach(..),
                ),
                "{}",
                call
            );
        }
    }

    #[test]
    fn include() {
        assert!(matches!(
            parse("include('test.inc');")
                .next()
                .unwrap()
                .unwrap()
                .kind(),
            &Include(..)
        ))
    }

    #[test]
    fn function() {
        assert!(matches!(
            parse("function register_packages( buf ) { return 1; }")
                .next()
                .unwrap()
                .unwrap()
                .kind(),
            &FunctionDeclaration(..)
        ));
        assert!(matches!(
            parse("function register_packages( ) { return 1; }")
                .next()
                .unwrap()
                .unwrap()
                .kind(),
            &FunctionDeclaration(..)
        ));
    }

    #[test]
    fn fct_anon_args() {
        let result = parse("_FCT_ANON_ARGS[0];").next().unwrap().unwrap();
        assert!(matches!(result.kind(), &Array(Some(_))));
        assert_eq!(
            result.as_token().category(),
            &Identifier(IdentifierType::FCTAnonArgs)
        );

        let result = parse("_FCT_ANON_ARGS;").next().unwrap().unwrap();
        assert!(matches!(result.kind(), &Array(None)));
        assert_eq!(
            result.as_token().category(),
            &Identifier(IdentifierType::FCTAnonArgs)
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
