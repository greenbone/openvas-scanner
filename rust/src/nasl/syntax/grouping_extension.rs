// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::{
    AssignOrder, Statement, StatementKind,
    error::SyntaxError,
    lexer::{End, Lexer},
    token::{Token, TokenKind},
};

use crate::{unclosed_token, unexpected_token};

pub(crate) trait Grouping {
    /// Parses (...)
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// Parses {...}
    fn parse_block(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// General Grouping parsing. Is called within prefix_extension.
    fn parse_grouping(&mut self, token: Token) -> Result<(End, Statement), SyntaxError>;
}

impl Grouping for Lexer {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.statement(0, &|cat| cat == &TokenKind::RightParen)?;

        match end {
            End::Done(end) => {
                self.depth = 0;
                Ok(match right.kind() {
                    StatementKind::Assign(cat, _, first, second) => {
                        Statement::with_start_end_token(
                            token,
                            end,
                            StatementKind::Assign(
                                cat.clone(),
                                AssignOrder::AssignReturn,
                                first.clone(),
                                second.clone(),
                            ),
                        )
                    }

                    _ => right,
                })
            }

            End::Continue => Err(unclosed_token!(token)),
        }
    }

    fn parse_block(&mut self, kw: Token) -> Result<Statement, SyntaxError> {
        let mut results = vec![];
        while let Some(token) = self.peek() {
            if token.kind() == &TokenKind::RightCurlyBracket {
                let _ = self.token();

                self.depth = 0;
                let stmt = Statement::with_start_end_token(
                    kw,
                    token.clone(),
                    StatementKind::Block(results),
                );
                return Ok(stmt);
            }
            let (end, stmt) = self.statement(0, &|cat| cat == &TokenKind::Semicolon)?;
            if end.is_done() && !matches!(stmt.kind(), StatementKind::NoOp) {
                results.push(stmt);
            }
        }
        Err(unclosed_token!(kw))
    }

    fn parse_grouping(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        fn as_done(stmt: Statement) -> (End, Statement) {
            (End::Done(stmt.end().clone()), stmt)
        }

        fn as_con(stmt: Statement) -> (End, Statement) {
            (End::Continue, stmt)
        }
        match token.kind() {
            TokenKind::LeftParen => self.parse_paren(token).map(as_con),
            TokenKind::LeftCurlyBracket => self.parse_block(token).map(as_done),
            TokenKind::LeftBrace => {
                let (end, right) = self.parse_comma_group(TokenKind::RightBrace)?;
                match end {
                    End::Done(end) => Ok((
                        End::Continue,
                        Statement::with_start_end_token(
                            token,
                            end,
                            StatementKind::Parameter(right),
                        ),
                    )),
                    End::Continue => Err(unclosed_token!(token)),
                }
            }
            _ => Err(unexpected_token!(token)),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::nasl::syntax::lexer::tests::parse_test_ok;

    parse_test_ok!(
        variables,
        r"
            {
                a = b + 1;
                b = a - --c;
                {
                   d = 23;
                }
            }
            "
    );
}
