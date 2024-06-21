// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Handles the prefix statement within Lexer
use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    keyword_extension::Keywords,
    lexer::{End, Lexer},
    operation::Operation,
    token::{Category, Token},
    unclosed_token, unexpected_end, unexpected_token, Statement, {AssignOrder, StatementKind},
};
pub(crate) trait Prefix {
    /// Handles statements before operation statements get handled.
    ///
    /// This must be called before handling postfix or infix operations to parse the initial statement.
    fn prefix_statement(
        &mut self,
        token: Token,
        abort: &impl Fn(&Category) -> bool,
    ) -> Result<(End, Statement), SyntaxError>;
}

/// Is used to verify operations.
fn prefix_binding_power(token: &Token) -> Result<u8, SyntaxError> {
    match token.category() {
        Category::Plus | Category::Minus | Category::Tilde | Category::Bang => Ok(21),
        _ => Err(unexpected_token!(token.clone())),
    }
}

impl<'a> Lexer<'a> {
    fn parse_variable(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        if !matches!(
            token.category(),
            Category::Identifier(crate::IdentifierType::Undefined(_))
        ) {
            return Err(unexpected_token!(token));
        }
        use End::*;
        let (kind, end) = {
            if let Some(nt) = self.peek() {
                match nt.category() {
                    Category::LeftParen => {
                        self.token();
                        let (end, params) = self.parse_comma_group(Category::RightParen)?;
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
                    Category::LeftBrace => {
                        self.token();
                        let (end, lookup) = self.statement(0, &|c| c == &Category::RightBrace)?;
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
        assign: Category,
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

impl<'a> Prefix for Lexer<'a> {
    fn prefix_statement(
        &mut self,
        token: Token,
        abort: &impl Fn(&Category) -> bool,
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
            Operation::Assign(Category::MinusMinus) => self
                .parse_prefix_assign_operator(Category::MinusMinus, token)
                .map(|stmt| (Continue, stmt)),
            Operation::Assign(Category::PlusPlus) => self
                .parse_prefix_assign_operator(Category::PlusPlus, token)
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

    use crate::{
        parse,
        token::{Category, Token},
        AssignOrder, Statement, StatementKind,
    };

    use Category::*;
    use StatementKind::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn operations() {
        let expected = |stmt: Statement, category: Category| match stmt.kind() {
            StatementKind::Operator(cat, _) => assert_eq!(cat, &category),
            kind => panic!("expected Operator, but got: {:?}", kind),
        };

        expected(result("-1;"), Category::Minus);
        expected(result("+1;"), Category::Plus);
        expected(result("~1;"), Category::Tilde);
        expected(result("!1;"), Category::Bang);
    }

    #[test]
    fn single_statement() {
        let no = Token {
            category: Number(1),
            line_column: (1, 1),
            position: (0, 1),
        };
        let data = Token {
            category: Data(vec![97]),
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
        let expected = |stmt: Statement, assign_operator: Category| match stmt.kind() {
            StatementKind::Assign(operator, AssignOrder::AssignReturn, _, _) => {
                assert_eq!(operator, &assign_operator)
            }
            kind => panic!("expected Assign, but got: {:?}", kind),
        };
        expected(result("++a;"), Category::PlusPlus);
        expected(result("--a;"), Category::MinusMinus);
        expected(result("++a[0];"), Category::PlusPlus);
        expected(result("--a[0];"), Category::MinusMinus);
    }
}
