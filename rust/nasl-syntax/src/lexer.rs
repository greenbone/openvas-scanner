// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Lexer is used to parse a single statement based on token::Tokenizer.
use std::ops::Not;

use crate::{
    error::SyntaxError,
    infix_extension::Infix,
    max_recursion,
    operation::Operation,
    postfix_extension::Postfix,
    prefix_extension::Prefix,
    token::{Category, Token, Tokenizer},
    unexpected_statement, unexpected_token, Statement, StatementKind,
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
