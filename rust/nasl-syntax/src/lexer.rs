// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Lexer is used to parse a single statement based on token::Tokenizer.
use std::ops::Not;

use crate::{
    error::SyntaxError,
    max_recursion,
    operation::Operation,
    postfix_extension::Postfix,
    prefix_extension::Prefix,
    token::{Category, Token, Tokenizer},
    unexpected_statement, unexpected_token, Statement, StatementKind, AssignOrder, unexpected_end,
};

/// Is used to parse Token to Statement
pub struct Lexer<'a> {
    // TODO: change to iterator of Token instead of Tokenizer
    // to allopw statements of a Vec
    tokenizer: Tokenizer<'a>,

    // is the current depth call within a statement call. The current
    // implementation relies that the iterator implementation resets depth to 0
    // after a statement, or error, has been returned.
    pub(crate) depth: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum End {
    // TODO remove Token from Done as it is in the returned Statement
    Done(Token),
    Continue,
}

/// Is the maximum depth allowed within one continuous statement call.
const MAX_DEPTH: u8 = 42;

impl End {
    pub fn is_done(&self) -> bool {
        match self {
            End::Done(_) => true,
            End::Continue => false,
        }
    }

    // pub fn category(&self) -> &Option<Category> {
    //     match self {
    //         End::Done(t) => &Some(t.category),
    //         End::Continue => &None,
    //     }
    // }
}

impl Not for End {
    type Output = bool;

    fn not(self) -> Self::Output {
        matches!(self, End::Continue)
    }
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

impl<'a> Lexer<'a> {
    /// Creates a Lexer
    pub fn new(tokenizer: Tokenizer<'a>) -> Lexer<'a> {
        let depth = 0;
        Lexer { tokenizer, depth }
    }

    /// Returns next token of tokenizer
    pub(crate) fn token(&mut self) -> Option<Token> {
        for token in self.tokenizer.by_ref() {
            if token.category() == &Category::Comment {
                continue;
            }
            return Some(token);
        }
        None
    }

    /// Returns peeks token of tokenizer
    pub(crate) fn peek(&mut self) -> Option<Token> {
        for token in self.tokenizer.clone() {
            if token.category() == &Category::Comment {
                continue;
            }
            return Some(token);
        }
        None
    }

    pub(crate) fn parse_comma_group(
        &mut self,
        category: Category,
    ) -> Result<(End, Vec<Statement>), SyntaxError> {
        let mut params = vec![];
        let mut end = End::Continue;
        while let Some(token) = self.peek() {
            if *token.category() == category {
                self.token();
                end = End::Done(token);
                break;
            }
            let (stmtend, param) =
                self.statement(0, &|c| c == &category || c == &Category::Comma)?;
            match param.kind() {
                StatementKind::Parameter(nparams) => params.extend_from_slice(nparams),
                _ => params.push(param),
            }
            match stmtend {
                End::Done(endcat) => {
                    if endcat.category() == &category {
                        end = End::Done(endcat);
                        break;
                    }
                }
                End::Continue => {}
            };
        }
        Ok((end, params))
    }

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


    /// Returns the next expression.
    ///
    /// It uses a prefix_extension to verify if a token is prefix relevant and if parsing should continue
    /// or stop. This is crucial for keyword handling.
    ///
    /// Afterwards it verifies via the postfix_extension if a token is postfix relevant.
    ///
    /// Last but not least it verifies if a token is infix relevant if the binding power of infix token
    /// is lower than the given min_bp it aborts. This is done to handle the correct operation order.
    pub(crate) fn statement(
        &mut self,
        min_binding_power: u8,
        abort: &impl Fn(&Category) -> bool,
    ) -> Result<(End, Statement), SyntaxError> {
        self.depth += 1;
        if self.depth >= MAX_DEPTH {
            return Err(max_recursion!(MAX_DEPTH));
        }
        fn done(token: Token, mut left: Statement) -> Result<(End, Statement), SyntaxError> {
            left.set_end(token.clone());
            Ok((End::Done(token), left))
        }

        fn cont(left: Statement) -> Result<(End, Statement), SyntaxError> {
            Ok((End::Continue, left))
        }
        // reset unhandled_token when min_bp is 0
        let (state, mut left) = self
            .token()
            .map(|token| {
                if token.is_faulty() {
                    return Err(unexpected_token!(token));
                }
                if abort(token.category()) {
                    let result = Statement::with_start_token(token.clone(), StatementKind::NoOp);
                    return done(token, result);
                }
                self.prefix_statement(token, abort)
            })
            .unwrap_or(Ok((
                End::Done(Token::unexpected_none()),
                Statement::without_token(StatementKind::EoF),
            )))?;
        match state {
            End::Continue => {}
            End::Done(x) => {
                return done(x, left);
            }
        }

        while let Some(token) = self.peek() {
            if abort(token.category()) {
                self.token();
                self.depth = 0;
                return done(token, left);
            }
            let op =
                Operation::new(token.clone()).ok_or_else(|| unexpected_token!(token.clone()))?;

            if self.needs_postfix(op.clone()) {
                let (end, stmt) = self
                    .postfix_statement(op, token.clone(), left)
                    .ok_or_else(|| unexpected_token!(token.clone()))??;
                self.token();
                left = stmt;
                if let End::Done(cat) = end {
                    self.depth = 0;
                    return done(cat, left);
                }
                continue;
            }

            if let Some(min_bp_reached) = self.needs_infix(&op, min_binding_power) {
                if !min_bp_reached {
                    // TODO could be changed to unexpected statement so that it doesn't need to be done in the iterator
                    return cont(left);
                }
                self.token();
                let (end, nl) = self.infix_statement(op, token, left, abort)?;
                left = nl;
                if let End::Done(cat) = end {
                    self.depth = 0;
                    return done(cat, left);
                } else {
                    // jump to the next without handling it as an error
                    continue;
                }
            }
            // Due to peeking it can end up in an endless loop
            return Err(unexpected_token!(token));
        }

        Ok((End::Continue, left))
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Statement, SyntaxError>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.statement(0, &|cat| cat == &Category::Semicolon);
        // simulate eof if end::continue is stuck in a recursive loop
        if self.depth >= MAX_DEPTH {
            return None;
        }

        match result {
            Ok((end, stmt)) => {
                if matches!(stmt.kind(), &StatementKind::EoF) {
                    return None;
                }
                if matches!(stmt.kind(), &StatementKind::NoOp) {
                    return Some(Ok(stmt));
                }
                match end {
                    End::Done(_) => Some(Ok(stmt)),
                    // This verifies if a statement was not finished yet; this can happen on assignments
                    // and missing semicolons.
                    End::Continue => Some(Err(unexpected_statement!(stmt))),
                }
            }
            Err(x) => Some(Err(x)),
        }
    }
}

#[cfg(test)]
mod infix {

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
