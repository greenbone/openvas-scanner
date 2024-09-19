// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Handles the postfix statement within Lexer
use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    operation::Operation,
    token::{Category, Token},
    unexpected_token, AssignOrder, Statement, StatementKind,
};

/// Is a trait to handle postfix statements.
pub(crate) trait Postfix {
    /// Returns true when an Operation needs a postfix handling.
    ///
    /// This is separated in two methods to prevent unnecessary clones of a previous statement.
    fn needs_postfix(&self, op: Operation) -> bool;
    /// Is the actual handling of postfix. The caller must ensure that needs_postfix is called previously.
    fn postfix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
    ) -> Option<Result<(End, Statement), SyntaxError>>;
}

impl<'a> Postfix for Lexer<'a> {
    fn postfix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
    ) -> Option<Result<(End, Statement), SyntaxError>> {
        match op {
            Operation::Assign(c) if matches!(c, Category::PlusPlus | Category::MinusMinus) => match lhs.kind() {
                StatementKind::Variable | StatementKind::Array(..) => Some(Ok((
                    End::Continue,
                    Statement::with_start_end_token(
                        lhs.end().clone(),
                        token,
                        StatementKind::Assign(
                            c,
                            AssignOrder::ReturnAssign,
                            Box::new(lhs),
                            Box::new(Statement::without_token(StatementKind::NoOp)),
                        ),
                    ),
                ))),
                _ => Some(Err(unexpected_token!(token))),
            },
            _ => None,
        }
    }

    fn needs_postfix(&self, op: Operation) -> bool {
        matches!(
            op,
            Operation::Grouping(Category::Comma)
                | Operation::Assign(Category::MinusMinus)
                | Operation::Assign(Category::PlusPlus)
        )
    }
}

#[cfg(test)]
mod test {
    use crate::{parse, token::Category, AssignOrder, Statement, StatementKind};

    use Category::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn variable_assignment_operator() {
        let expected = |stmt: Statement, assign_operator: Category| match stmt.kind() {
            StatementKind::Assign(operator, AssignOrder::ReturnAssign, _, _) => {
                assert_eq!(operator, &assign_operator)
            }
            kind => panic!("expected Assign, but got: {:?}", kind),
        };
        expected(result("a++;"), PlusPlus);
        expected(result("a--;"), MinusMinus);
        expected(result("a[1]++;"), PlusPlus);
        expected(result("a[1]--;"), MinusMinus);
    }
}
