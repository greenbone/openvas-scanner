// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Handles the prefix statement within Lexer
use super::{
    error::SyntaxError,
    grouping_extension::Grouping,
    keyword_extension::Keywords,
    lexer::{End, Lexer},
    operation::Operation,
    token::{Token, TokenKind},
    Statement, {AssignOrder, StatementKind},
};

use crate::{nasl::syntax::Keyword, unclosed_token, unexpected_end, unexpected_token};

pub(crate) trait Prefix {
    /// Handles statements before operation statements get handled.
    ///
    /// This must be called before handling postfix or infix operations to parse the initial statement.
    fn prefix_statement(
        &mut self,
        token: Token,
        abort: &impl Fn(&TokenKind) -> bool,
    ) -> Result<(End, Statement), SyntaxError>;
}

/// Is used to verify operations.
fn prefix_binding_power(token: &Token) -> Result<u8, SyntaxError> {
    match token.kind() {
        TokenKind::Plus | TokenKind::Minus | TokenKind::Tilde | TokenKind::Bang => Ok(21),
        _ => Err(unexpected_token!(token.clone())),
    }
}

impl Lexer {
    fn parse_variable(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        if !matches!(token.kind(), TokenKind::Identifier(Keyword::Undefined(_))) {
            return Err(unexpected_token!(token));
        }
        use End::*;
        let (kind, end) = {
            if let Some(nt) = self.peek() {
                match nt.kind() {
                    TokenKind::LeftParen => {
                        self.token();
                        let (end, params) = self.parse_comma_group(TokenKind::RightParen)?;
                        match end {
                            Done(end) => {
                                let params = Statement::with_start_end_token(
                                    nt,
                                    end.clone(),
                                    StatementKind::Parameter(params),
                                );
                                Ok((StatementKind::Call(Box::new(params)), end))
                            }
                            Continue => Err(unclosed_token!(nt)),
                        }
                    }
                    TokenKind::LeftBrace => {
                        self.token();
                        let (end, lookup) = self.statement(0, &|c| c == &TokenKind::RightBrace)?;
                        let lookup = lookup.as_returnable_or_err()?;
                        match end {
                            Done(end) => Ok((StatementKind::Array(Some(Box::new(lookup))), end)),
                            Continue => Err(unclosed_token!(token.clone())),
                        }
                    }
                    _ => Ok((StatementKind::Variable, token.clone())),
                }
            } else {
                Ok((StatementKind::Variable, token.clone()))
            }
        }?;
        let stmt = Statement::with_start_end_token(token, end, kind);

        Ok((Continue, stmt))
    }

    /// Parses Operations that have an prefix (e.g. -1)
    fn parse_prefix_assign_operator(
        &mut self,
        assign: TokenKind,
        token: Token,
    ) -> Result<Statement, SyntaxError> {
        let next = self
            .token()
            .ok_or_else(|| unexpected_end!("parsing prefix statement"))?;
        let (_, stmt) = self.parse_variable(next)?;
        if !matches!(
            stmt.kind(),
            StatementKind::Variable | StatementKind::Array(..)
        ) {
            return Err(unexpected_token!(token));
        }
        Ok(Statement::with_start_end_token(
            token.clone(),
            stmt.end().clone(),
            StatementKind::Assign(
                assign,
                AssignOrder::AssignReturn,
                Box::new(stmt),
                Box::new(Statement::without_token(StatementKind::NoOp)),
            ),
        ))
    }
}

impl Prefix for Lexer {
    fn prefix_statement(
        &mut self,
        token: Token,
        abort: &impl Fn(&TokenKind) -> bool,
    ) -> Result<(End, Statement), SyntaxError> {
        use End::*;
        let op = Operation::new(&token).ok_or_else(|| unexpected_token!(token.clone()))?;
        match op {
            Operation::Operator(kind) => {
                let bp = prefix_binding_power(&token)?;
                let (end, right) = self.statement(bp, abort)?;
                let stmt = Statement::with_start_end_token(
                    token,
                    right.end().clone(),
                    StatementKind::Operator(kind, vec![right]),
                );
                Ok((end, stmt))
            }
            Operation::Primitive => Ok((
                Continue,
                Statement::with_start_token(token, StatementKind::Primitive),
            )),
            Operation::Variable => self.parse_variable(token),
            Operation::Grouping(_) => self.parse_grouping(token),
            Operation::Assign(TokenKind::MinusMinus) => self
                .parse_prefix_assign_operator(TokenKind::MinusMinus, token)
                .map(|stmt| (Continue, stmt)),
            Operation::Assign(TokenKind::PlusPlus) => self
                .parse_prefix_assign_operator(TokenKind::PlusPlus, token)
                .map(|stmt| (Continue, stmt)),
            Operation::Assign(_) => Err(unexpected_token!(token)),
            Operation::Keyword(keyword) => self.parse_keyword(keyword, token),
            Operation::NoOp => Ok((
                Done(token.clone()),
                Statement::with_start_token(token, StatementKind::NoOp),
            )),
        }
    }
}

#[cfg(test)]
mod test {

    use super::super::{
        parse,
        token::{Token, TokenKind},
        AssignOrder, Statement, StatementKind,
    };

    use StatementKind::*;
    use TokenKind::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn operations() {
        let expected = |stmt: Statement, kind1: TokenKind| match stmt.kind() {
            StatementKind::Operator(kind2, _) => assert_eq!(kind2, &kind1),
            kind => panic!("expected Operator, but got: {:?}", kind),
        };

        expected(result("-1;"), TokenKind::Minus);
        expected(result("+1;"), TokenKind::Plus);
        expected(result("~1;"), TokenKind::Tilde);
        expected(result("!1;"), TokenKind::Bang);
    }

    #[test]
    fn single_statement() {
        let no = Token {
            kind: Number(1),
            line_column: (1, 1),
            position: (0, 1),
        };
        let data = Token {
            kind: Data(vec![97]),
            line_column: (1, 1),
            position: (0, 3),
        };
        let one = result("1;");
        assert_eq!(one.kind(), &Primitive);
        assert_eq!(one.start(), &no);
        let second = result("'a';");
        assert_eq!(second.kind(), &Primitive);
        assert_eq!(second.start(), &data);
    }

    #[test]
    fn assignment_operator() {
        let expected = |stmt: Statement, assign_operator: TokenKind| match stmt.kind() {
            StatementKind::Assign(operator, AssignOrder::AssignReturn, _, _) => {
                assert_eq!(operator, &assign_operator)
            }
            kind => panic!("expected Assign, but got: {:?}", kind),
        };
        expected(result("++a;"), TokenKind::PlusPlus);
        expected(result("--a;"), TokenKind::MinusMinus);
        expected(result("++a[0];"), TokenKind::PlusPlus);
        expected(result("--a[0];"), TokenKind::MinusMinus);
    }
}
