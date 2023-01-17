//! Handles the postfix statement within Lexer
use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    operation::Operation,
    token::{Category, Token},
    unexpected_token, Statement, AssignOrder,
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

impl<'a> Lexer<'a> {
    fn as_assign_statement(
        lhs: Statement,
        token: Token,
        assign: Category,
    ) -> Option<Result<(End, Statement), SyntaxError>> {
        match lhs {
            Statement::Variable(token) => Some(Ok((
                End::Continue,
                Statement::Assign(
                    assign,
                    AssignOrder::ReturnAssign,
                    Box::new(Statement::Variable(token)),
                    Box::new(Statement::NoOp(None)),
                ),
            ))),
            Statement::Array(token, resolver) => Some(Ok((
                End::Continue,
                Statement::Assign(
                    assign,
                    AssignOrder::ReturnAssign,
                    Box::new(Statement::Array(token, resolver)),
                    Box::new(Statement::NoOp(None)),
                ),
            ))),
            _ => Some(Err(unexpected_token!(token))),
        }
    }
}

impl<'a> Postfix for Lexer<'a> {
    fn postfix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
    ) -> Option<Result<(End, Statement), SyntaxError>> {
        match op {
            Operation::Assign(Category::PlusPlus) => {
                Self::as_assign_statement(lhs, token, Category::PlusPlus)
            }
            Operation::Assign(Category::MinusMinus) => {
                Self::as_assign_statement(lhs, token, Category::MinusMinus)
            }
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
    use crate::{
        parse,
        token::{Category, Token}, Statement, AssignOrder,
    };

    
    use Category::*;
    use crate::Statement::*;
    use crate::IdentifierType::Undefined;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn variable_assignment_operator() {
        let expected = |assign_operator: Category| {
            Operator(
                Plus,
                vec![
                    Primitive(Token {
                        category: Number(1),
                        position: (1, 1),
                    }),
                    Operator(
                        Star,
                        vec![
                            Assign(
                                assign_operator,
                                AssignOrder::ReturnAssign,
                                Box::new(Variable(Token {
                                    category: Identifier(Undefined("a".to_owned())),
                                    position: (1, 5),
                                })),
                                Box::new(NoOp(None)),
                            ),
                            Primitive(Token {
                                category: Number(1),
                                position: (1, 11),
                            }),
                        ],
                    ),
                ],
            )
        };
        assert_eq!(result("1 + a++ * 1;"), expected(PlusPlus));
        assert_eq!(result("1 + a-- * 1;"), expected(MinusMinus));
    }

    #[test]
    fn array_assignment_operator() {
        use AssignOrder::*;
        let expected = |assign_operator: Category| {
            Assign(
                assign_operator,
                ReturnAssign,
                Box::new(Array(
                    Token {
                        category: Identifier(Undefined("a".to_owned())),
                        position: (1, 1),
                    },
                    Some(Box::new(Primitive(Token {
                        category: Number(1),
                        position: (1, 3),
                    }))),
                )),
                Box::new(NoOp(None)),
            )
        };
        assert_eq!(result("a[1]++;"), expected(PlusPlus));
        assert_eq!(result("a[1]--;"), expected(MinusMinus));
    }
}
