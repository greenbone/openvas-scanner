// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    token::{Category, Token},
    unclosed_token, unexpected_token, AssignOrder, Statement, StatementKind,
};

pub(crate) trait Grouping {
    /// Parses (...)
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// Parses {...}
    fn parse_block(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// General Grouping parsing. Is called within prefix_extension.
    fn parse_grouping(&mut self, token: Token) -> Result<(End, Statement), SyntaxError>;
}

impl<'a> Grouping for Lexer<'a> {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.statement(0, &|cat| cat == &Category::RightParen)?;

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
            if token.category() == &Category::RightCurlyBracket {
                let _ = self.token();

                self.depth = 0;
                let stmt = Statement::with_start_end_token(
                    kw,
                    token.clone(),
                    StatementKind::Block(results),
                );
                return Ok(stmt);
            }
            let (end, stmt) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
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
        match token.category() {
            Category::LeftParen => self.parse_paren(token).map(as_con),
            Category::LeftCurlyBracket => self.parse_block(token).map(as_done),
            Category::LeftBrace => {
                let (end, right) = self.parse_comma_group(Category::RightBrace)?;
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
    use crate::{parse, StatementKind};

    use StatementKind::*;

    fn result(code: &str) -> StatementKind {
        parse(code).next().unwrap().unwrap().kind().clone()
    }

    #[test]
    fn variables() {
        let stmt = result(
            r"
            {
                a = b + 1;
                b = a - --c;
                {
                   d = 23;
                }
            }
            ",
        );
        assert!(matches!(stmt, Block(..)));
    }
}
