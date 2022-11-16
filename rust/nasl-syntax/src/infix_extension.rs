//! Handles the infix statement within Lexer

use crate::{
    error::SyntaxError,
    lexer::Lexer,
    lexer::{AssignOrder, Statement},
    operation::Operation,
    token::{Category, Token},
    unexpected_end, unexpected_statement,
};
pub(crate) trait Infix {
    /// Returns true when an Operation needs a infix handling.
    ///
    /// This is separated in two methods to prevent unnecessary clones of a previos statement.
    fn needs_infix(&self, op: Operation, min_bp: u8) -> Option<bool>;

    /// Is the actual handling of infix. The caller must ensure that needs_infix is called previously.
    fn infix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
        abort: &impl Fn(Category) -> bool,
    ) -> Result<(bool, Statement), SyntaxError>;
}

/// Returns the binding power of a operation or None.
///
/// The binding power is used to express the order of a statement.
/// Because the binding power of e,g. Plus is lower than Star the Star operation gets calculate before.
/// The first number represents the left hand, the second number the right hand binding power
fn infix_binding_power(op: Operation) -> Option<(u8, u8)> {
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
        Assign(_) => (2, 3),
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
        abort: &impl Fn(Category) -> bool,
    ) -> Result<(bool, Statement), SyntaxError> {
        Ok({
            // binding power of the right side
            let (_, right_bp) =
                infix_binding_power(op).expect("handle_infix should be called first");
            let (end, rhs) = self.statement(right_bp, abort)?;
            let stmt = match op {
                // DoublePoint operation needs to be changed to NamedParameter statement
                Operation::Assign(Category::DoublePoint) => match lhs {
                    Statement::Variable(left) => {
                        // if the right side is a parameter we need to transform the NamedParameter 
                        // from the atomar params and assign the first one to the NamedParameter instead
                        // of Statement::Parameter and put it upfront
                        match rhs {
                            Statement::Parameter(mut params) => {
                                params.reverse();
                                let value = params.pop().ok_or_else(|| unexpected_end!("while getting value of named parameter"))?;
                                let np = Statement::NamedParameter(left, Box::new(value));
                                params.push(np);
                                params.reverse();
                                Statement::Parameter(params)
                            }

                            _ => Statement::NamedParameter(left, Box::new(rhs)),
                        }
                    },
                    _ => return Err(unexpected_statement!(lhs)),
                },
                // Assign needs to be translated due handle the return cases for e.g. ( a = 1) * 2
                Operation::Assign(category) => match lhs {
                    Statement::Variable(var) => {
                        // when the right side is a parameter list than it is an array
                        let lhs = {
                            match rhs {
                                Statement::Parameter(_) => Statement::Array(var, None),
                                _ => lhs,
                            }
                        };
                        Statement::Assign(
                            category,
                            AssignOrder::Assign,
                            Box::new(lhs),
                            Box::new(rhs),
                        )
                    }
                    Statement::Array(_, _) => Statement::Assign(
                        category,
                        AssignOrder::Assign,
                        Box::new(lhs),
                        Box::new(rhs),
                    ),
                    _ => Statement::Operator(token.category(), vec![lhs, rhs]),
                },
                _ => Statement::Operator(token.category(), vec![lhs, rhs]),
            };
            (end, stmt)
        })
    }

    fn needs_infix(&self, op: Operation, min_bp: u8) -> Option<bool> {
        let (l_bp, _) = infix_binding_power(op)?;
        if l_bp < min_bp {
            Some(false)
        } else {
            Some(true)
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::token::Base;
    use crate::token::Base::*;
    use crate::token::Category::*;
    use crate::token::StringCategory;
    use crate::token::Token;
    use Statement::*;

    // simplified resolve method to verify a calculate with a given statement
    fn resolve(code: &str, s: Statement) -> i64 {
        let callable = |mut stmts: Vec<Statement>, calculus: Box<dyn Fn(i64, i64) -> i64>| -> i64 {
            let right = stmts.pop().unwrap();
            let left = stmts.pop().unwrap();
            calculus(resolve(code, left), resolve(code, right))
        };
        let single_callable =
            |mut stmts: Vec<Statement>, calculus: Box<dyn Fn(i64) -> i64>| -> i64 {
                let left = stmts.pop().unwrap();
                calculus(resolve(code, left))
            };
        match s {
            Primitive(token) => match token.category() {
                Number(_) => code[token.range()].parse().unwrap(),
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

    fn token(category: Category, start: usize, end: usize) -> Token {
        Token {
            category,
            position: (start, end),
        }
    }

    fn result(code: &str) -> Statement {
        crate::parse(code).next().unwrap().unwrap()
    }

    macro_rules! calculated_test {
        ($code:expr, $expected:expr) => {
            let expr = crate::parse($code).next().unwrap().unwrap();
            assert_eq!(resolve($code, expr), $expected);
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
        use Statement::*;
        fn expected(category: Category, shift: usize) -> Statement {
            Assign(
                category,
                AssignOrder::Assign,
                Box::new(Variable(token(Identifier(None), 0, 1))),
                Box::new(Primitive(token(Number(Base10), 5 + shift, 6 + shift))),
            )
        }
        assert_eq!(result("a += 1;"), expected(PlusEqual, 0));
        assert_eq!(result("a -= 1;"), expected(MinusEqual, 0));
        assert_eq!(result("a /= 1;"), expected(SlashEqual, 0));
        assert_eq!(result("a *= 1;"), expected(StarEqual, 0));
        assert_eq!(result("a >>= 1;"), expected(GreaterGreaterEqual, 1));
        assert_eq!(result("a <<= 1;"), expected(LessLessEqual, 1));
        assert_eq!(result("a >>>= 1;"), expected(GreaterGreaterGreaterEqual, 2));
    }

    #[test]
    fn compare_operator() {
        use Category::*;
        use Statement::*;
        fn expected(category: Category, shift: i32) -> Statement {
            Operator(
                category,
                vec![
                    Variable(Token {
                        category: Identifier(None),
                        position: (0, 1),
                    }),
                    Primitive(Token {
                        category: String(StringCategory::Quoteable),
                        position: ((6 + shift) as usize, (7 + shift) as usize),
                    }),
                ],
            )
        }
        assert_eq!(result("a !~ '1';"), expected(BangTilde, 0));
        assert_eq!(result("a =~ '1';"), expected(EqualTilde, 0));
        assert_eq!(result("a >< '1';"), expected(GreaterLess, 0));
        assert_eq!(result("a >!< '1';"), expected(GreaterBangLess, 1));
        assert_eq!(result("a == '1';"), expected(EqualEqual, 0));
        assert_eq!(result("a != '1';"), expected(BangEqual, 0));
        assert_eq!(result("a > '1';"), expected(Greater, -1));
        assert_eq!(result("a < '1';"), expected(Less, -1));
        assert_eq!(result("a >= '1';"), expected(GreaterEqual, 0));
        assert_eq!(result("a <= '1';"), expected(LessEqual, 0));
    }

    #[test]
    fn locical_operator() {
        fn expected(category: Category, shift: usize) -> Statement {
            Operator(
                category,
                vec![
                    Variable(Token {
                        category: Identifier(None),
                        position: (0, 1),
                    }),
                    Primitive(Token {
                        category: Number(Base::Base10),
                        position: (5 + shift, 6 + shift),
                    }),
                ],
            )
        }
        assert_eq!(result("a && 1;"), expected(AmpersandAmpersand, 0));
        assert_eq!(result("a || 1;"), expected(PipePipe, 0));
    }

    #[test]
    fn assignment() {
        assert_eq!(
            result("a = 1;"),
            Assign(
                Category::Equal,
                AssignOrder::Assign,
                Box::new(Variable(token(Identifier(None), 0, 1))),
                Box::new(Primitive(Token {
                    category: Number(Base10),
                    position: (4, 5)
                }))
            )
        );
        assert_eq!(
            result("(a = 1);"),
            Assign(
                Category::Equal,
                AssignOrder::AssignReturn,
                Box::new(Variable(token(Identifier(None), 1, 2))),
                Box::new(Primitive(Token {
                    category: Number(Base10),
                    position: (5, 6)
                }))
            )
        );
    }
}
