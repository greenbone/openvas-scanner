// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::{End, Lexer},
    token::{Category, IdentifierType, Token},
    unclosed_statement, unclosed_token, unexpected_end, unexpected_statement, unexpected_token,
    variable_extension::CommaGroup,
    Statement,
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
    fn parse_declaration(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
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
        let result = Statement::Declare(token, params);
        Ok((end, result))
    }
    fn parse_if(&mut self, kw: Token) -> Result<(End, Statement), SyntaxError> {
        let ptoken = self.token().ok_or_else(|| unexpected_end!("if parsing"))?;
        let condition = match ptoken.category() {
            Category::LeftParen => self.parse_paren(ptoken.clone())?,
            _ => return Err(unexpected_token!(ptoken.clone())),
        }
        .as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
        if end == End::Continue {
            return Err(unclosed_token!(ptoken));
        }
        let (ekw, r#else, end) = {
            match self.peek() {
                Some(token) => match token.category() {
                    Category::Identifier(IdentifierType::Else) => {
                        self.token();
                        let (end, stmt) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
                        if end == End::Continue {
                            return Err(unexpected_statement!(stmt));
                        }
                        (Some(token), Some(stmt), end)
                    }
                    _ => (None, None, end),
                },
                None => (None, None, end),
            }
        };
        Ok((
            end,
            Statement::If(
                kw,
                Box::new(condition),
                Box::new(body),
                ekw,
                r#else.map(Box::new),
            ),
        ))
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

    fn parse_call_return_params(&mut self) -> Result<(End, Statement), SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, parameter) = self.statement(0, &|cat| cat == &Category::RightParen)?;
        let parameter = parameter.as_returnable_or_err()?;
        match end {
            End::Done(end) => Ok((End::Done(end), parameter)),
            End::Continue => Err(unexpected_end!("exit")),
        }
    }

    fn parse_exit(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        // TODO maybe refactor to reuse function call and hindsight verification
        let (end, parameter) = self.parse_call_return_params()?;
        let (_, should_be_semicolon) = self.statement(0, &|cat| cat == &Category::Semicolon)?;

        if !matches!(should_be_semicolon, Statement::NoOp(_)) {
            // exit must be followed by ; nothing else
            return Err(unexpected_statement!(should_be_semicolon));
        }
        match end {
            End::Done(end) => Ok((
                End::Done(end.clone()),
                Statement::Exit(token, Box::new(parameter), end),
            )),
            End::Continue => Err(unexpected_statement!(parameter)),
        }
    }

    fn parse_include(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        // TODO maybe refactor to reuse function call and hindsight verification
        let (end, parameter) = self.parse_call_return_params()?;
        let (_, should_be_semicolon) = self.statement(0, &|cat| cat == &Category::Semicolon)?;

        if !matches!(should_be_semicolon, Statement::NoOp(_)) {
            // exit must be followed by ; nothing else
            return Err(unexpected_statement!(should_be_semicolon));
        }
        match end {
            End::Done(end) => Ok((
                End::Done(end.clone()),
                Statement::Include(token, Box::new(parameter), end),
            )),
            End::Continue => Err(unexpected_statement!(parameter)),
        }
    }

    fn parse_function(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
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

        let block = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(block.category(), Category::LeftCurlyBracket) {
            return Err(unexpected_token!(block));
        }
        let (end, block) = self.parse_block(block)?;
        Ok((
            End::Done(end),
            Statement::FunctionDeclaration(
                token,
                id,
                parameter,
                parameter_end_token,
                Box::new(block),
            ),
        ))
    }

    fn parse_return(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        if let Some(sc) = self.peek() {
            if matches!(sc.category(), Category::Semicolon) {
                self.token();
                return Ok((
                    End::Done(sc.clone()),
                    Statement::Return(token, Box::new(Statement::NoOp(Some(sc)))),
                ));
            }
        }
        let (end, parameter) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
        let parameter = parameter.as_returnable_or_err()?;
        if let End::Done(cat) = end {
            Ok((
                End::Done(cat),
                Statement::Return(token, Box::new(parameter)),
            ))
        } else {
            Err(unexpected_end!("exit"))
        }
    }
    fn parse_continue(&mut self, kw: Token) -> Result<(End, Statement), SyntaxError> {
        let token = self.peek();
        if let Some(token) = token {
            if matches!(token.category(), Category::Semicolon) {
                self.token();
                return Ok((End::Done(token), Statement::Continue(kw)));
            } else {
                return Err(unexpected_token!(token));
            }
        }
        Err(unexpected_end!("exit"))
    }
    fn parse_break(&mut self, kw: Token) -> Result<(End, Statement), SyntaxError> {
        let token = self.peek();
        if let Some(token) = token {
            if matches!(token.category(), Category::Semicolon) {
                self.token();
                return Ok((End::Done(token), Statement::Break(kw)));
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

    fn parse_for(&mut self, kw: Token) -> Result<(End, Statement), SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, assignment) = self.statement(0, &|c| c == &Category::Semicolon)?;
        if !matches!(
            assignment,
            Statement::Assign(_, _, _, _) | Statement::NoOp(_)
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
                    Statement::NoOp(None),
                )
            }
            _ => self
                .statement(0, &|c| c == &Category::RightParen)
                .map_err(Self::map_syntax_error_to_unclosed_left_paren)?,
        };
        if !matches!(end.category(), Some(Category::RightParen)) {
            let ut = update.as_token();
            return Err(unclosed_token!(Token {
                category: Category::LeftParen,
                line_column: ut.map_or_else(|| (0, 0), |t| t.line_column),
                position: ut.map_or_else(|| (0, 0), |t| t.position)
            }));
        }
        let (end, body) = self.statement(0, &|c| c == &Category::Semicolon)?;
        match end {
            End::Done(cat) => Ok((
                End::Done(cat),
                Statement::For(
                    kw,
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
        let (end, condition) = self
            .statement(0, &|c| c == &Category::RightParen)
            .map_err(Self::map_syntax_error_to_unclosed_left_paren)?;
        let ct = condition.as_token();
        if !matches!(end.category(), Some(Category::RightParen)) {
            return Err(unclosed_token!(Token {
                category: Category::LeftParen,
                line_column: ct.map_or_else(|| (0, 0), |t| t.line_column),
                position: ct.map_or_else(|| (0, 0), |t| t.position),
            }));
        }
        let condition = condition.as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|c| c == &Category::Semicolon)?;
        match end {
            End::Done(end) => Ok((
                End::Done(end),
                Statement::While(token, Box::new(condition), Box::new(body)),
            )),
            End::Continue => Err(unclosed_token!(token)),
        }
    }
    fn parse_repeat(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        let (end, body) = self.statement(0, &|c| c == &Category::Semicolon)?;

        if !end {
            return Err(unclosed_token!(token));
        }
        let (until, end): (Statement, Token) = {
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
        Ok((
            End::Done(end),
            Statement::Repeat(token, Box::new(body), Box::new(until)),
        ))
    }

    fn parse_foreach(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
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
            End::Done(end) => Ok((
                End::Done(end),
                Statement::ForEach(token, variable, Box::new(r#in), Box::new(block)),
            )),
            End::Continue => Err(unclosed_token!(token)),
        }
    }
    fn parse_fct_anon_args(&mut self, keyword: Token) -> Result<(End, Statement), SyntaxError> {
        match self.peek() {
            Some(token) => match token.category() {
                Category::LeftBrace => {
                    self.token();
                    let (end, lookup) = self.statement(0, &|c| c == &Category::RightBrace)?;
                    let lookup = lookup.as_returnable_or_err()?;
                    match end {
                        End::Done(end) => Ok((
                            End::Continue,
                            Statement::Array(keyword, Some(Box::new(lookup)), Some(end)),
                        )),
                        End::Continue => Err(unclosed_token!(token)),
                    }
                }
                _ => Ok((End::Continue, Statement::Array(keyword, None, None))),
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
            IdentifierType::For => self.parse_for(token),
            IdentifierType::ForEach => self.parse_foreach(token),
            IdentifierType::If => self.parse_if(token),
            IdentifierType::Else => Err(unexpected_token!(token)), // handled in if
            IdentifierType::While => self.parse_while(token),
            IdentifierType::Repeat => self.parse_repeat(token),
            IdentifierType::Until => Err(unexpected_token!(token)), // handled in repeat
            IdentifierType::LocalVar | IdentifierType::GlobalVar => self.parse_declaration(token),
            IdentifierType::Null => Ok((End::Continue, Statement::Primitive(token))),
            IdentifierType::Return => self.parse_return(token),
            IdentifierType::Include => self.parse_include(token),
            IdentifierType::Exit => self.parse_exit(token),
            IdentifierType::FCTAnonArgs => self.parse_fct_anon_args(token),
            IdentifierType::True => Ok((End::Continue, Statement::Primitive(token))),
            IdentifierType::False => Ok((End::Continue, Statement::Primitive(token))),
            IdentifierType::Function => self.parse_function(token),
            IdentifierType::ACT(_) => Ok((End::Continue, Statement::AttackCategory(token))),
            IdentifierType::Undefined(_) => Err(unexpected_token!(token)),
            IdentifierType::Continue => self.parse_continue(token),
            IdentifierType::Break => self.parse_break(token),
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        parse,
        token::{Category, IdentifierType, Token},
        Statement,
    };

    use crate::Statement::*;
    use crate::TokenCategory::*;

    #[test]
    fn if_statement() {
        let actual = parse("if (description) script_oid('1'); else display('hi');")
            .next()
            .unwrap()
            .unwrap();
        match actual {
            If(_, _, _, Some(_), Some(_)) => {}
            _ => unreachable!("{actual} must be if with else stmt."),
        }

        let actual = parse("if( version[1] ) report += '\nVersion: ' + version[1];")
            .next()
            .unwrap()
            .unwrap();
        match actual {
            If(_, _, _, None, None) => {}
            _ => unreachable!("{actual} must be if without else stmt."),
        }
    }

    #[test]
    fn if_block() {
        let actual = parse("if (description) { ; }").next().unwrap().unwrap();
        match actual {
            If(_, _, b, _, _) => match *b {
                Block(_, v, _) => {
                    assert_eq!(v, vec![]);
                }
                _ => unreachable!("{b} must be a block stmt."),
            },
            _ => unreachable!("{actual} must be an if stmt."),
        }
    }

    #[test]
    fn local_var() {
        let expected = |actual: Statement, scope: Category| match actual {
            Declare(a, vars) => {
                assert_eq!(a.category(), &scope);
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
        match parse("NULL;").next().unwrap().unwrap() {
            Primitive(Token {
                category: Identifier(IdentifierType::Null),
                line_column: _,
                position: _,
            }) => {
                // correct
            }
            actual => unreachable!("{actual} must be a primitive stmt."),
        }
    }

    #[test]
    fn boolean() {
        match parse("TRUE;").next().unwrap().unwrap() {
            Primitive(Token {
                category: Identifier(IdentifierType::True),
                line_column: _,
                position: _,
            }) => {
                // correct
            }
            actual => unreachable!("{actual} must be a primitive stmt."),
        }
        match parse("FALSE;").next().unwrap().unwrap() {
            Primitive(Token {
                category: Identifier(IdentifierType::False),
                line_column: _,
                position: _,
            }) => {
                // correct
            }
            actual => unreachable!("{actual} must be a primitive stmt."),
        }
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
                    parse(&format!("{call};")).next().unwrap().unwrap(),
                    Exit(..),
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
                    parse(&format!("{call};")).next().unwrap().unwrap(),
                    Return(..),
                ),
                "{}",
                call
            );
        }
    }

    #[test]
    fn for_loop() {
        let code = "for (i = 0; i < 10; i++) display('hi');";
        assert!(matches!(parse(code).next().unwrap().unwrap(), For(..)));
        let code = "for (i = 0; i < 10; ) i = 10;";
        assert!(matches!(parse(code).next().unwrap().unwrap(), For(..)))
    }

    #[test]
    fn while_loop() {
        let code = "while (TRUE) ;";
        assert!(matches!(parse(code).next().unwrap().unwrap(), While(..)))
    }

    #[test]
    fn repeat_loop() {
        let code = "repeat ; until 1 == 1;";
        assert!(matches!(parse(code).next().unwrap().unwrap(), Repeat(..)))
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
                    parse(&format!("{call};")).next().unwrap().unwrap(),
                    ForEach(..),
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
            Include(..)
        ))
    }

    #[test]
    fn function() {
        assert!(matches!(
            parse("function register_packages( buf ) { return 1; }")
                .next()
                .unwrap()
                .unwrap(),
            FunctionDeclaration(..)
        ));
        assert!(matches!(
            parse("function register_packages( ) { return 1; }")
                .next()
                .unwrap()
                .unwrap(),
            FunctionDeclaration(..)
        ));
    }

    #[test]
    fn fct_anon_args() {
        match parse("_FCT_ANON_ARGS[0];").next().unwrap().unwrap() {
            Array(
                Token {
                    category: Category::Identifier(IdentifierType::FCTAnonArgs),
                    line_column: _,
                    position: _,
                },
                Some(_),
                Some(_),
            ) => {}
            actual => unreachable!("{actual} must be an array."),
        }
        match parse("_FCT_ANON_ARGS;").next().unwrap().unwrap() {
            Array(
                Token {
                    category: Category::Identifier(IdentifierType::FCTAnonArgs),
                    line_column: _,
                    position: _,
                },
                None,
                None,
            ) => {}
            actual => unreachable!("{actual} must be an array."),
        }
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
