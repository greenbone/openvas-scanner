//! Lexer is used to parse a single statement based on token::Tokenizer.
use std::ops::Not;

use crate::{
    error::SyntaxError,
    infix_extension::Infix,
    operation::Operation,
    postfix_extension::Postfix,
    prefix_extension::Prefix,
    token::{Category, Token, Tokenizer},
    unexpected_statement, unexpected_token, Statement,
};



/// Is used to parse Token to Statement
pub struct Lexer<'a> {
    tokenizer: Tokenizer<'a>,
    pub(crate) unhandled_token: Option<Token>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum End {
    Done(Category),
    Continue,
}

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

impl<'a> Lexer<'a> {
    /// Creates a Lexer
    pub fn new(tokenizer: Tokenizer<'a>) -> Lexer<'a> {
        Lexer {
            tokenizer,
            unhandled_token: None,
        }
    }

    /// Returns next token of tokenizer
    pub(crate) fn token(&mut self) -> Option<Token> {
        while let Some(token) = self
            .unhandled_token
            .take()
            .or_else(|| self.tokenizer.next())
        {
            if token.category() == Category::Comment {
                continue;
            }
            return Some(token);
        }
        None
    }

    /// Returns the next expression.
    ///
    /// It uses a prefix_extension to verify if a token is prefix relevant and if parsing should continue
    /// or stop. This is crucial for keyword handling.
    ///
    /// Afterwards it verifies via the postifx_extension if a token is postfix relevant.
    ///
    /// Last but not least it verifies if a token is infix relevant if the binding power of infix token
    /// is lower than the given min_bp it aborts. This is done to handle the correct operation order.
    pub(crate) fn statement(
        &mut self,
        min_binding_power: u8,
        abort: &impl Fn(Category) -> bool,
    ) -> Result<(End, Statement), SyntaxError> {
        // reset unhandled_token when min_bp is 0
        let (state, mut left) = self
            .token()
            .map(|token| {
                if token.is_faulty() {
                    return Err(unexpected_token!(token));
                }
                if abort(token.category()) {
                    return Ok((
                        End::Done(Category::UnknownSymbol),
                        Statement::NoOp(Some(token)),
                    ));
                }
                self.prefix_statement(token, abort)
            })
            .unwrap_or(Ok((
                End::Done(Category::UnknownSymbol),
                Statement::EoF,
            )))?;
        match state {
            End::Continue => {}
            end => return Ok((end, left)),
        }

        let mut end_statement = End::Continue;
        loop {
            let token = {
                match self.token() {
                    Some(x) => x,
                    None => break,
                }
            };
            if abort(token.category()) {
                end_statement = End::Done(token.category());
                break;
            }
            let op = Operation::new(token).ok_or_else(|| unexpected_token!(token))?;

            if self.needs_postfix(op) {
                let (end, stmt) = self
                    .postfix_statement(op, token, left)
                    .expect("needs postfix should have been validated before")?;
                left = stmt;
                if let End::Done(cat) = end {
                    end_statement = End::Done(cat);
                    break;
                }
                continue;
            }

            if let Some(min_bp_reached) = self.needs_infix(op, min_binding_power) {
                if !min_bp_reached {
                    self.unhandled_token = Some(token);
                    break;
                }
                let (end, nl) = self.infix_statement(op, token, left, abort)?;
                left = nl;
                if let End::Done(cat) = end {
                    end_statement = End::Done(cat);
                    break;
                }
            }
        }

        Ok((end_statement, left))
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Statement, SyntaxError>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.statement(0, &|cat| cat == Category::Semicolon);
        match result {
            Ok((_, Statement::EoF)) => None,
            Ok((End::Done(_), stmt)) => Some(Ok(stmt)),
            Ok((End::Continue, stmt)) => {
                if matches!(stmt, Statement::NoOp(_)) {
                    Some(Ok(stmt))
                } else {
                    Some(Err(unexpected_statement!(stmt)))
                }
            }
            Err(x) => Some(Err(x)),
        }
    }
}
