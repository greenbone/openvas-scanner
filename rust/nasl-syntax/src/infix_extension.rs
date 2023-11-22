// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Handles the infix statement within Lexer

use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    operation::Operation,
    token::{Category, Token},
    unexpected_end, unexpected_statement, Statement, {AssignOrder, StatementKind},
};
pub(crate) trait Infix {
    /// Returns true when an Operation needs a infix handling.
    ///
    /// This is separated in two methods to prevent unnecessary clones of a previous statement.
    fn needs_infix(&self, op: &Operation, min_bp: u8) -> Option<bool>;

    /// Is the actual handling of infix. The caller must ensure that needs_infix is called previously.
    fn infix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
        abort: &impl Fn(&Category) -> bool,
    ) -> Result<(End, Statement), SyntaxError>;
}

/// Returns the binding power of a operation or None.
///
/// The binding power is used to express the order of a statement.
/// Because the binding power of e,g. Plus is lower than Star the Star operation gets calculate before.
/// The first number represents the left hand, the second number the right hand binding power
fn infix_binding_power(op: &Operation) -> Option<(u8, u8)> {
    use self::Operation::*;
    use Category::*;
    let res = match op {
        Operator(Category::StarStar) => (22, 23),
        Operator(Category::Star | Category::Slash | Category::Percent) => (20, 21),
        Operator(Plus | Minus) => (18, 19),
        Operator(LessLess | GreaterGreater | GreaterGreaterGreater) => (16, 17),
        Operator(Ampersand) => (14, 15),
        Operator(Caret) => (12, 13),
        Operator(Pipe) => (10, 11),
        Operator(
            Less | LessEqual | Greater | GreaterEqual | EqualEqual | BangEqual | GreaterLess
            | GreaterBangLess | EqualTilde | BangTilde,
        ) => (8, 9),
        Operator(AmpersandAmpersand) => (6, 7),
        Operator(PipePipe) => (4, 5),
        // two is lowest since on block we can start with 1
        Assign(_) | Operator(X) => (2, 3),

        _ => return None,
    };
    Some(res)
}

impl<'a> Lexer<'a> {}

impl<'a> Infix for Lexer<'a> {
    fn infix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
        abort: &impl Fn(&Category) -> bool,
    ) -> Result<(End, Statement), SyntaxError> {
        Ok({
            // binding power of the right side
            let (_, right_bp) =
                infix_binding_power(&op).expect("handle_infix should be called first");
            // probably better to change EoF to error instead of Ok(Continue) to not have to double check each time
            let (mut end, rhs) = self.statement(right_bp, abort)?;
            // this feels like a hack ... maybe better to use an own abort condition for the right side instead?
            // TODO set end token to token when done
            if let End::Done(ref x) = end {
                if !abort(x.category()) {
                    end = End::Continue;
                }
            }
            if matches!(rhs.kind(), StatementKind::EoF) {
                return Ok((End::Done(token), rhs));
            }

            let end_token = match &end {
                End::Done(x) => x.clone(),
                End::Continue => rhs.end().clone(),
            };
            let start_token = lhs.start().clone();
            let build_stmt = |k| Statement::with_start_end_token(start_token, end_token, k);

            let stmt = match op {
                // DoublePoint operation needs to be changed to NamedParameter statement
                Operation::Assign(Category::DoublePoint) => {
                    match lhs.kind() {
                        StatementKind::Variable => {
                            // if the right side is a parameter we need to transform the NamedParameter
                            // from the atomic params and assign the first one to the NamedParameter instead
                            // of Statement::Parameter and put it upfront
                            match rhs.kind() {
                                StatementKind::Parameter(params) => {
                                    // TODO flatten
                                    first_element_as_named_parameter(params.clone())?
                                }

                                _ => build_stmt(StatementKind::NamedParameter(Box::new(rhs))),
                            }
                        }
                        StatementKind::Parameter(params) => match rhs.kind() {
                            StatementKind::Parameter(right_params) => {
                                let mut params = params.clone();
                                params.extend_from_slice(right_params);
                                build_stmt(StatementKind::Parameter(params))
                            }
                            _ => {
                                let mut params = params.clone();
                                params.push(rhs);
                                build_stmt(StatementKind::Parameter(params))
                            }
                        },
                        _ => return Err(unexpected_statement!(lhs)),
                    }
                }
                // Assign needs to be translated due handle the return cases for e.g. ( a = 1) * 2
                Operation::Assign(category) => match lhs.kind() {
                    StatementKind::Variable => {
                        let lhs = match rhs.kind() {
                            StatementKind::Parameter(..) => Statement::with_start_end_token(
                                lhs.start().clone(),
                                rhs.end().clone(),
                                StatementKind::Array(None),
                            ),
                            _ => lhs,
                        };

                        build_stmt(StatementKind::Assign(
                            category,
                            AssignOrder::AssignReturn,
                            Box::new(lhs),
                            Box::new(rhs),
                        ))
                    }
                    StatementKind::Array(..) => build_stmt(StatementKind::Assign(
                        category,
                        AssignOrder::AssignReturn,
                        Box::new(lhs),
                        Box::new(rhs),
                    )),

                    _ => build_stmt(StatementKind::Operator(
                        token.category().clone(),
                        vec![lhs, rhs],
                    )),
                },
                _ => build_stmt(StatementKind::Operator(
                    token.category().clone(),
                    vec![lhs, rhs],
                )),
            };
            (end, stmt)
        })
    }

    fn needs_infix(&self, op: &Operation, min_bp: u8) -> Option<bool> {
        let (l_bp, _) = infix_binding_power(op)?;
        if l_bp < min_bp {
            Some(false)
        } else {
            Some(true)
        }
    }
}

// if the right side is a parameter we need to transform the NamedParameter
// from the atomic params and assign the first one to the NamedParameter instead
// of Statement::Parameter and put it upfront
fn first_element_as_named_parameter(mut params: Vec<Statement>) -> Result<Statement, SyntaxError> {
    params.reverse();
    let value = params
        .pop()
        .ok_or_else(|| unexpected_end!("while getting value of named parameter"))?;
    let np = StatementKind::NamedParameter(Box::new(value));
    params.push(Statement::without_token(np));
    params.reverse();
    Ok(Statement::without_token(StatementKind::Parameter(params)))
}

#[cfg(test)]
mod test {

    use core::panic;

    use super::*;

    use crate::token::Category::*;
    
    
    use StatementKind::*;

    // simplified resolve method to verify a calculate with a given statement
    fn resolve(s: &Statement) -> i64 {
        let callable = |stmts: &[Statement], calculus: Box<dyn Fn(i64, i64) -> i64>| -> i64 {
            let right = &stmts[1];
            let left = &stmts[0];
            calculus(resolve(left), resolve(right))
        };
        let single_callable = |stmts: &[Statement], calculus: Box<dyn Fn(i64) -> i64>| -> i64 {
            let left = &stmts[0];
            calculus(resolve(left))
        };
        match s.kind() {
            Primitive => match s.start().category() {
                Number(num) => *num,
                String(_) => todo!(),
                _ => todo!(),
            },
            Operator(head, rest) => match head {
                Tilde => single_callable(rest, Box::new(|left| !left)),
                Plus => callable(rest, Box::new(|left, right| left + right)),
                Minus if rest.len() == 1 => single_callable(rest, Box::new(|left| -left)),
                Minus => callable(rest, Box::new(|left, right| left - right)),
                Star => callable(rest, Box::new(|left, right| left * right)),
                Slash => callable(rest, Box::new(|left, right| left / right)),
                Percent => callable(rest, Box::new(|left, right| left % right)),
                LessLess => callable(rest, Box::new(|left, right| left << right)),
                GreaterGreater => callable(rest, Box::new(|left, right| left >> right)),
                Ampersand => callable(rest, Box::new(|left, right| left & right)),
                Pipe => callable(rest, Box::new(|left, right| left | right)),
                Caret => callable(rest, Box::new(|left, right| left ^ right)),
                GreaterGreaterGreater => {
                    callable(
                        rest,
                        Box::new(|left, right| {
                            // this operator is used to drop signed bits
                            // so the result depends heavily if it is u32, u64, ...
                            // to have the same results as in javascript we use u32 in this example
                            let left_casted = left as u32;
                            (left_casted >> right) as i64
                        }),
                    )
                }
                StarStar => callable(
                    rest,
                    Box::new(|left, right| (left as u32).pow(right as u32) as i64),
                ),
                token => {
                    todo!("{:?}", token)
                }
            },
            _ => todo!("operator not found"),
        }
    }

    fn result(code: &str) -> Statement {
        crate::parse(code).next().unwrap().unwrap()
    }

    macro_rules! calculated_test {
        ($code:expr, $expected:expr) => {
            let expr = crate::parse($code).next().unwrap().unwrap();
            assert_eq!(resolve(&expr), $expected);
        };
    }

    #[test]
    fn ordering() {
        calculated_test!("1 + 5 * 6;", 31);
        calculated_test!("3 * 10 + 10 / 5;", 32);
        calculated_test!("3 * 10 / 5;", 6);
        calculated_test!("3 * 10 / 5 % 4;", 2);
    }

    #[test]
    fn grouping() {
        //calculated_test!("2 * (2 + 5);", 13);
        calculated_test!("(2 + 5) * 2;", 14);
    }

    #[test]
    fn pow() {
        calculated_test!("2 ** 4;", 16);
    }

    #[test]
    fn bitwise_operations() {
        //shifting
        calculated_test!("1 << 2 * 3;", 64);
        calculated_test!("3 * 12 >> 2;", 9);
        calculated_test!("-5 >>> 2;", 1073741822);
        // operations
        calculated_test!("1 & 0;", 0);
        calculated_test!("~1 | 0;", -2);
        calculated_test!("1 ^ 1;", 0);
    }

    #[test]
    fn operator_assignment() {
        use Category::*;
        fn expected(stmt: Statement, category: Category) {
            match stmt.kind() {
                StatementKind::Assign(cat, AssignOrder::AssignReturn, ..) => {
                    assert_eq!(cat, &category);
                }
                kind => panic!("Expected Assign, got: {:?}", kind),
            }
        }
        expected(result("a += 1;"), PlusEqual);
        expected(result("a -= 1;"), MinusEqual);
        expected(result("a /= 1;"), SlashEqual);
        expected(result("a *= 1;"), StarEqual);
        expected(result("a %= 1;"), PercentEqual);
        expected(result("a >>= 1;"), GreaterGreaterEqual);
        expected(result("a <<= 1;"), LessLessEqual);
        expected(result("a >>>= 1;"), GreaterGreaterGreaterEqual);
    }

    #[test]
    fn compare_operator() {
        use Category::*;

        fn expected(stmt: Statement, category: Category) {
            match stmt.kind() {
                StatementKind::Operator(cat, ..) => {
                    assert_eq!(cat, &category);
                }
                kind => panic!("Expected Operator, got: {:?}", kind),
            }
        }
        expected(result("a !~ '1';"), BangTilde);
        expected(result("a =~ '1';"), EqualTilde);
        expected(result("a >< '1';"), GreaterLess);
        expected(result("a >!< '1';"), GreaterBangLess);
        expected(result("a == '1';"), EqualEqual);
        expected(result("a != '1';"), BangEqual);
        expected(result("a > '1';"), Greater);
        expected(result("a < '1';"), Less);
        expected(result("a >= '1';"), GreaterEqual);
        expected(result("a <= '1';"), LessEqual);
        expected(result("x() x 2;"), X);
    }

    #[test]
    fn logical_operator() {
        fn expected(stmt: Statement, category: Category) {
            match stmt.kind() {
                StatementKind::Operator(cat, ..) => {
                    assert_eq!(cat, &category);
                }
                kind => panic!("Expected Operator, got: {:?}", kind),
            }
        }
        expected(result("a && 1;"), AmpersandAmpersand);
        expected(result("a || 1;"), PipePipe);
    }

    #[test]
    fn assignment() {
        fn expected(stmt: Statement, category: Category) {
            match stmt.kind() {
                StatementKind::Assign(cat, AssignOrder::AssignReturn, ..) => {
                    assert_eq!(cat, &category);
                }
                kind => panic!("Expected Assign, got: {:?}", kind),
            }
        }
        expected(result("(a = 1);"), Category::Equal);
    }
}
