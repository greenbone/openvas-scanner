// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    token::{Category, Token},
    unclosed_token, unexpected_token,
    variable_extension::CommaGroup,
    AssignOrder, Statement,
};

pub(crate) trait Grouping {
    /// Parses (...)
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError>;
    /// Parses {...}
    fn parse_block(&mut self, token: Token) -> Result<(Token, Statement), SyntaxError>;
    /// General Grouping parsing. Is called within prefix_extension.
    fn parse_grouping(&mut self, token: Token) -> Result<(End, Statement), SyntaxError>;
}

impl<'a> Lexer<'a> {
    fn parse_brace(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.parse_comma_group(Category::RightBrace)?;
        match end {
            End::Done(_end) => Ok(Statement::Parameter(right)),
            End::Continue => Err(unclosed_token!(token)),
        }
    }
}

impl<'a> Grouping for Lexer<'a> {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        let (end, right) = self.statement(0, &|cat| cat == &Category::RightParen)?;
        if !end {
            Err(unclosed_token!(token))
        } else {
            match right {
                Statement::Assign(category, _, variable, stmt) => Ok(Statement::Assign(
                    category,
                    AssignOrder::AssignReturn,
                    variable,
                    stmt,
                )),
                _ => Ok(right),
            }
        }
    }

    fn parse_block(&mut self, kw: Token) -> Result<(Token, Statement), SyntaxError> {
        let mut results = vec![];
        while let Some(token) = self.peek() {
            if token.category() == &Category::RightCurlyBracket {
                self.token();
                return Ok((token.clone(), Statement::Block(kw, results, token)));
            }
            let (end, stmt) = self.statement(0, &|cat| cat == &Category::Semicolon)?;
            if end.is_done() && !matches!(stmt, Statement::NoOp(_)) {
                results.push(stmt);
            }
        }
        Err(unclosed_token!(kw))
    }

    fn parse_grouping(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        match token.category() {
            Category::LeftParen => self.parse_paren(token).map(|stmt| (End::Continue, stmt)),
            Category::LeftCurlyBracket => self
                .parse_block(token)
                .map(|(end, stmt)| (End::Done(end), stmt)),
            Category::LeftBrace => self.parse_brace(token).map(|stmt| (End::Continue, stmt)),
            _ => Err(unexpected_token!(token)),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{parse, Statement};

    use Statement::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
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
