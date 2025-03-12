// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::{End, Lexer},
    token::{Keyword, Token, TokenKind},
    ErrorKind, Ident, Statement, StatementKind,
};
use crate::{
    unclosed_statement, unclosed_token, unexpected_end, unexpected_statement, unexpected_token,
};

pub(crate) trait Keywords {
    /// Parses keywords.
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(End, Statement), SyntaxError>;
}

impl Lexer {
    fn parse_declaration(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, params) = self.parse_comma_group(TokenKind::Semicolon)?;
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
        let condition = match ptoken.kind() {
            TokenKind::LeftParen => self.parse_paren(ptoken.clone())?,
            _ => return Err(unexpected_token!(ptoken.clone())),
        }
        .as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;
        let end = {
            match end {
                End::Done(end) => end,
                End::Continue => return Err(unclosed_token!(ptoken)),
            }
        };

        let (ekw, r#else, end) = {
            match self.peek() {
                Some(token) => match token.kind() {
                    TokenKind::Keyword(Keyword::Else) => {
                        self.token();
                        let (end, stmt) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;

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
        if token.kind() != &TokenKind::LeftParen {
            Err(unexpected_token!(token))
        } else {
            Ok(())
        }
    }

    fn parse_call_return_params(&mut self) -> Result<Statement, SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, parameter) = self.statement(0, &|cat| cat == &TokenKind::RightParen)?;
        let parameter = parameter.as_returnable_or_err()?;
        match end {
            End::Done(_) => Ok(parameter),
            End::Continue => Err(unexpected_end!("exit")),
        }
    }

    fn parse_exit(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        // TODO maybe refactor to reuse function call and hindsight verification
        let parameter = self.parse_call_return_params()?;
        let (_, should_be_semicolon) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;

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
        let (_, should_be_semicolon) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;

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
        if !matches!(id.kind(), TokenKind::Ident(_)) {
            return Err(unexpected_token!(id));
        }
        let paren = self
            .token()
            .ok_or_else(|| unexpected_end!("parse_function"))?;
        if !matches!(paren.kind(), TokenKind::LeftParen) {
            return Err(unexpected_token!(paren));
        }
        let (gend, parameter) = self.parse_comma_group(TokenKind::RightParen)?;
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
        if !matches!(block.kind(), TokenKind::LeftCurlyBracket) {
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
            if matches!(sc.kind(), TokenKind::Semicolon) {
                self.token();
                return Ok(Statement::with_start_end_token(
                    token,
                    sc.clone(),
                    StatementKind::Return(Box::new(Statement::without_token(StatementKind::NoOp))),
                ));
            }
        }
        let (end, parameter) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;
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
            if matches!(token.kind(), TokenKind::Semicolon) {
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
            if matches!(token.kind(), TokenKind::Semicolon) {
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
            ErrorKind::UnexpectedToken(k) => unclosed_token!(Token {
                kind: TokenKind::LeftParen,
                position: k.position,
            }),
            _ => e,
        }
    }

    fn is_end_of_token(end: &End, kind: TokenKind) -> bool {
        match end {
            End::Done(x) => x.kind() == &kind,
            End::Continue => false,
        }
    }

    fn parse_for(&mut self, kw: Token) -> Result<Statement, SyntaxError> {
        self.jump_to_left_parenthesis()?;
        let (end, assignment) = self.statement(0, &|c| c == &TokenKind::Semicolon)?;
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
        let (end, condition) = self.statement(0, &|c| c == &TokenKind::Semicolon)?;
        let condition = condition.as_returnable_or_err()?;
        if end == End::Continue {
            return Err(unclosed_statement!(condition));
        }
        let (end, update) = match self.peek() {
            // no update statement provided
            Some(Token {
                kind: TokenKind::RightParen,
                position,
            }) => {
                self.token();
                (
                    End::Done(Token {
                        kind: TokenKind::RightParen,
                        position,
                    }),
                    Statement::without_token(StatementKind::NoOp),
                )
            }
            _ => self
                .statement(0, &|c| c == &TokenKind::RightParen)
                .map_err(Self::map_syntax_error_to_unclosed_left_paren)?,
        };
        if !Self::is_end_of_token(&end, TokenKind::RightParen) {
            let ut = update.as_token();
            return Err(unclosed_token!(Token {
                kind: TokenKind::LeftParen,
                position: ut.position
            }));
        }
        let (end, body) = self.statement(0, &|c| c == &TokenKind::Semicolon)?;
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
            .statement(0, &|c| c == &TokenKind::RightParen)
            .map_err(Self::map_syntax_error_to_unclosed_left_paren)?;
        let ct = condition.as_token();
        if !Self::is_end_of_token(&end, TokenKind::RightParen) {
            return Err(unclosed_token!(Token {
                kind: TokenKind::LeftParen,
                position: ct.position,
            }));
        }
        let condition = condition.as_returnable_or_err()?;
        let (end, body) = self.statement(0, &|c| c == &TokenKind::Semicolon)?;
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
        let (end, body) = self.statement(0, &|c| c == &TokenKind::Semicolon)?;

        if !end {
            return Err(unclosed_token!(token));
        }
        let (until, end) = {
            match self.token() {
                Some(token) => match token.kind() {
                    TokenKind::Keyword(Keyword::Until) => {
                        let (end, stmt) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;
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
                Some(token) => match token.kind() {
                    TokenKind::Ident(Ident(_)) => Ok(token),
                    _ => Err(unexpected_token!(token)),
                },
                None => Err(unexpected_end!("in foreach")),
            }?
        };
        let r#in: Statement = {
            let token = self.token().ok_or_else(|| unexpected_end!("in foreach"))?;
            match token.kind() {
                TokenKind::LeftParen => self
                    .parse_paren(token.clone())
                    .map_err(|_| unclosed_token!(token)),
                _ => Err(unexpected_token!(token)),
            }?
        };
        let (end, block) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;
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
            Some(token) => match token.kind() {
                TokenKind::LeftBrace => {
                    self.token();
                    let (end, lookup) = self.statement(0, &|c| c == &TokenKind::RightBrace)?;
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

impl Keywords for Lexer {
    fn parse_keyword(
        &mut self,
        keyword: Keyword,
        token: Token,
    ) -> Result<(End, Statement), SyntaxError> {
        match keyword {
            Keyword::For => self
                .parse_for(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::ForEach => self
                .parse_foreach(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::If => self
                .parse_if(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::Else => Err(unexpected_token!(token)), // handled in if
            Keyword::While => self
                .parse_while(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::Repeat => self
                .parse_repeat(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::Until => Err(unexpected_token!(token)), // handled in repeat
            Keyword::LocalVar | Keyword::GlobalVar => self
                .parse_declaration(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::Return => self
                .parse_return(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::Include => self
                .parse_include(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::Exit => self
                .parse_exit(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::FCTAnonArgs => self
                .parse_fct_anon_args(token)
                .map(|stmt| (End::Continue, stmt)),
            Keyword::ACT(_) => Ok((
                End::Continue,
                Statement::with_start_token(token, StatementKind::AttackCategory),
            )),
            Keyword::Function => self
                .parse_function(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
            Keyword::Continue => self
                .parse_continue(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),

            Keyword::Break => self
                .parse_break(token)
                .map(|stmt| (End::Done(stmt.end().clone()), stmt)),
        }
    }
}

#[cfg(test)]
mod test {

    use crate::nasl::syntax::lexer::tests::{parse_test_err, parse_test_ok};

    parse_test_ok!(
        if_else_statement,
        "if (description) script_oid('1'); else display('hi');"
    );
    parse_test_ok!(
        if_statement,
        "if( version[1] ) report += '\nVersion: ' + version[1];"
    );
    parse_test_ok!(if_block, "if (description) { ; }");

    parse_test_ok!(local_var, "local_var a, b, c;");
    parse_test_ok!(global_var, "global_var a, b, c;");

    parse_test_ok!(null, "NULL;");
    parse_test_ok!(boolean_true, "TRUE;");
    parse_test_ok!(boolean_false, "FALSE;");
    parse_test_ok!(
        exit,
        "exit(1); exit(a); exit(a(b)); exit(23 + 5); exit((4 * 5));"
    );
    parse_test_ok!(
        r#return,
        "return 1; return a; return a(b); return 23 + 5; return (4 * 5);"
    );
    parse_test_ok!(for_loop, "for (i = 0; i < 10; i++) display('hi');");
    parse_test_ok!(for_loop_empty_assignment, "for (i = 0; i < 10; ) i = 10;");
    parse_test_ok!(while_loop, "while (TRUE) ;");
    parse_test_ok!(repeat_loop, "repeat ; until 1 == 1;");
    parse_test_ok!(
        foreach,
        "foreach info(list) { display(info); }",
        "foreach info(make_list('a', 'b')) { display(info); }"
    );
    parse_test_ok!(include, "include('test.inc');");
    parse_test_ok!(
        function,
        "function register_packages( ) { return 1; }",
        "function register_packages( buf ) { return 1; }"
    );
    parse_test_ok!(fct_anon_args, "_FCT_ANON_ARGS[0];", "_FCT_ANON_ARGS;");

    parse_test_err!(
        unclosed,
        "local_var a, b, c",
        "local_var a, 1, c;",
        "local_var 1;",
        "if (description) { ; ",
        "if (description) display(1)",
    );
}
