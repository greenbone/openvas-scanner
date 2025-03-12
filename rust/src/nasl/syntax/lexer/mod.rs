// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::ops::Not;

use super::{
    error::SyntaxError,
    operation::Operation,
    prefix_extension::Prefix,
    token::{Token, TokenKind},
    AssignOrder, Statement, StatementKind,
};

use crate::{max_recursion, unexpected_statement, unexpected_token};

#[derive(Default, Clone, Copy)]
struct TokenIndex(usize);

/// Is used to parse Token to Statement
#[derive(Clone)]
pub struct Lexer {
    tokens: Vec<Token>,
    position: TokenIndex,

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
    use TokenKind::*;
    let res = match op {
        Operator(TokenKind::StarStar) => (22, 23),
        Operator(TokenKind::Star | TokenKind::Slash | TokenKind::Percent) => (20, 21),
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

enum InFixState {
    NoInfix,
    ReturnContinue(Statement),
    ReturnEnd(Token, Statement),
    Unfinished(Statement),
}

impl Lexer {
    /// Creates a Lexer
    pub fn new(tokens: Vec<Token>) -> Lexer {
        let depth = 0;
        Lexer {
            tokens,
            depth,
            position: TokenIndex(0),
        }
    }

    /// Returns next token of tokenizer
    pub(crate) fn token(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position.0).cloned();
        self.position.0 += 1;
        token
    }

    /// Returns peeks token of tokenizer
    pub(crate) fn peek(&mut self) -> Option<Token> {
        self.tokens.get(self.position.0).cloned()
    }

    pub(crate) fn parse_comma_group(
        &mut self,
        kind: TokenKind,
    ) -> Result<(End, Vec<Statement>), SyntaxError> {
        let mut params = vec![];
        let mut end = End::Continue;
        while let Some(token) = self.peek() {
            if *token.kind() == kind {
                self.token();
                end = End::Done(token);
                break;
            }
            let (stmtend, param) = self.statement(0, &|c| c == &kind || c == &TokenKind::Comma)?;
            match param.kind() {
                StatementKind::Parameter(nparams) => params.extend_from_slice(nparams),
                _ => params.push(param),
            }
            match stmtend {
                End::Done(endcat) => {
                    if endcat.kind() == &kind {
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
        right_bp: u8,
        token: Token,
        lhs: Statement,
        abort: &impl Fn(&TokenKind) -> bool,
    ) -> Result<(End, Statement), SyntaxError> {
        let (end, rhs) = self.statement(right_bp, abort)?;
        if matches!(rhs.kind(), StatementKind::EoF) {
            return Ok((End::Done(token), rhs));
        }
        let end_token = match &end {
            End::Done(x) if abort(x.kind()) => x.clone(),
            End::Done(_) | End::Continue => rhs.end().clone(),
        };
        let start_token = lhs.start().clone();
        let build_stmt = |k| Statement::with_start_end_token(start_token, end_token, k);

        let stmt = match op {
            // DoublePoint operation needs to be changed to NamedParameter statement
            Operation::Assign(TokenKind::DoublePoint) => {
                match lhs.kind() {
                    StatementKind::Variable => {
                        // if the right side is a parameter we need to transform the NamedParameter
                        // from the atomic params and assign the first one to the NamedParameter instead
                        // of Statement::Parameter and put it upfront
                        build_stmt(StatementKind::NamedParameter(Box::new(rhs)))
                    }
                    _ => return Err(unexpected_statement!(lhs)),
                }
            }
            // Assign needs to be translated due handle the return cases for e.g. ( a = 1) * 2
            Operation::Assign(kind) => match lhs.kind() {
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
                        kind,
                        AssignOrder::AssignReturn,
                        Box::new(lhs),
                        Box::new(rhs),
                    ))
                }
                StatementKind::Array(..) => build_stmt(StatementKind::Assign(
                    kind,
                    AssignOrder::AssignReturn,
                    Box::new(lhs),
                    Box::new(rhs),
                )),

                _ => build_stmt(StatementKind::Operator(
                    token.kind().clone(),
                    vec![lhs, rhs],
                )),
            },
            _ => build_stmt(StatementKind::Operator(
                token.kind().clone(),
                vec![lhs, rhs],
            )),
        };
        Ok((end, stmt))
    }

    /// Returns an infix state
    ///
    /// On NoInfix the operation is not infix based.
    /// On ReturnContinue the operation does not have the required binding power.
    /// On ReturnEnd the statement is finished.
    /// On Unfinished the upper loop should continue while caching the statement.
    fn handle_infix(
        &mut self,
        op: Operation,
        min_bp: u8,
        token: Token,
        left: Statement,
        abort: &impl Fn(&TokenKind) -> bool,
    ) -> Result<InFixState, SyntaxError> {
        // returns three states 1. not handled, 2. return continue, 3. return done 4. continue
        // loop

        Ok(match infix_binding_power(&op) {
            None => InFixState::NoInfix,
            Some((x, _)) if x < min_bp => InFixState::ReturnContinue(left),
            Some((_, y)) => {
                self.token();
                let (end, nl) = self.infix_statement(op, y, token, left, abort)?;
                match end {
                    End::Done(cat) => {
                        self.depth = 0;
                        InFixState::ReturnEnd(cat, nl)
                    }
                    End::Continue => InFixState::Unfinished(nl),
                }
            }
        })
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
        abort: &impl Fn(&TokenKind) -> bool,
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
                if abort(token.kind()) {
                    let result = Statement::with_start_token(token.clone(), StatementKind::NoOp);
                    return done(token, result);
                }
                self.prefix_statement(token, abort)
            })
            .unwrap_or(Ok((
                End::Done(Token::sentinel()),
                Statement::without_token(StatementKind::EoF),
            )))?;
        match state {
            End::Continue => {}
            End::Done(x) => {
                return done(x, left);
            }
        }

        while let Some(token) = self.peek() {
            if abort(token.kind()) {
                self.token();
                self.depth = 0;
                return done(token, left);
            }
            let op = Operation::new(&token).ok_or_else(|| unexpected_token!(token.clone()))?;
            match op {
                Operation::Assign(c)
                    if matches!(c, TokenKind::PlusPlus | TokenKind::MinusMinus) =>
                {
                    let token = self.token().expect("expected token");
                    match left.kind() {
                        StatementKind::Variable | StatementKind::Array(..) => {
                            left = Statement::with_start_end_token(
                                left.end().clone(),
                                token,
                                StatementKind::Assign(
                                    c.clone(),
                                    AssignOrder::ReturnAssign,
                                    Box::new(left),
                                    Box::new(Statement::without_token(StatementKind::NoOp)),
                                ),
                            );
                        }
                        _ => return Err(unexpected_token!(token)),
                    }
                }
                op => {
                    match self.handle_infix(op, min_binding_power, token.clone(), left, abort)? {
                        InFixState::NoInfix => return Err(unexpected_token!(token)),
                        InFixState::ReturnContinue(left) => return cont(left),
                        InFixState::ReturnEnd(cat, left) => return done(cat, left),
                        InFixState::Unfinished(nl) => {
                            left = nl;
                            continue;
                        }
                    }
                }
            }
        }

        Ok((End::Continue, left))
    }
}

impl Iterator for Lexer {
    type Item = Result<Statement, SyntaxError>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.statement(0, &|cat| cat == &TokenKind::Semicolon);
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
