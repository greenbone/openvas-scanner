//! Handles the postfix statement within Lexer
use crate::{
    error::SyntaxError,
    lexer::Lexer,
    lexer::{AssignOrder, Statement},
    operation::Operation,
    token::{Category, Token},
    unexpected_token,
};

/// Is a trait to handle postfix statements.
pub(crate) trait Postfix {
    /// Returns true when an Operation needs a postfix handling.
    ///
    /// This is separated in two methods to prevent unnecessary clones of a previos statement.
    fn needs_postfix(&self, op: Operation) -> bool;
    /// Is the actual handling of postfix. The caller must ensure that needs_postfix is called previously.
    fn postfix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
        abort: &impl Fn(Category) -> bool,
    ) -> Option<Result<Statement, SyntaxError>>;
}

impl<'a> Lexer<'a> {
    fn flatten_parameter(
        &mut self,
        lhs: Statement,
        abort: &impl Fn(Category) -> bool,
    ) -> Result<Statement, SyntaxError> {
        let mut lhs = match lhs {
            Statement::Parameter(x) => x,
            x => vec![x],
        };
        match self.statement(0, abort)? {
            Statement::Parameter(mut x) => lhs.append(&mut x),
            x => lhs.push(x),
        };
        Ok(Statement::Parameter(lhs))
    }

    fn as_assign_statement(
        lhs: Statement,
        token: Token,
        assign: Category,
        operation: Category,
    ) -> Option<Result<Statement, SyntaxError>> {
        match lhs {
            Statement::Variable(token) => Some(Ok(Statement::Assign(
                assign,
                AssignOrder::ReturnAssign,
                Box::new(Statement::Variable(token)),
                Box::new(Statement::Operator(
                    operation,
                    vec![
                        Statement::Variable(token),
                        Statement::RawNumber(1),
                    ],
                )),
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
        abort: &impl Fn(Category) -> bool,
    ) -> Option<Result<Statement, SyntaxError>> {
        match op {
            Operation::Grouping(Category::Comma) => Some(self.flatten_parameter(lhs, abort)),
            Operation::Assign(Category::PlusPlus) => {
                Self::as_assign_statement(lhs, token, Category::PlusPlus, Category::Plus)
            }
            Operation::Assign(Category::MinusMinus) => {
                Self::as_assign_statement(lhs, token, Category::MinusMinus, Category::Minus)
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
        lexer::AssignOrder,
        lexer::Statement,
        parse,
        token::{Base, Category, Token},
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn postfix_assignment_operator() {
        let expected = |assign_operator: Category, operator: Category| {
            Operator(
                Plus,
                vec![
                    Primitive(Token {
                        category: Number(Base10),
                        position: (0, 1),
                    }),
                    Operator(
                        Star,
                        vec![
                            Assign(
                                assign_operator,
                                AssignOrder::ReturnAssign,
                                Box::new(Variable(Token {
                                    category: Identifier(None),
                                    position: (4, 5),
                                })),
                                Box::new(Operator(
                                    operator,
                                    vec![
                                        Variable(Token {
                                            category: Identifier(None),
                                            position: (4, 5),
                                        }),
                                        RawNumber(1),
                                    ],
                                )),
                            ),
                            Primitive(Token {
                                category: Number(Base10),
                                position: (10, 11),
                            }),
                        ],
                    ),
                ],
            )
        };
        assert_eq!(result("1 + a++ * 1"), expected(PlusPlus, Plus));
        assert_eq!(result("1 + a-- * 1"), expected(MinusMinus, Minus));
    }
}
