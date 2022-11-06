use core::fmt;
use std::{ops::Range, error::Error};

use crate::token::Token;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenError {
    reason: String,
    token: Option<Token>,
    position: Option<Range<usize>>,
}

impl TokenError {
    pub fn unexpected_token(token: Token) -> TokenError {
        TokenError {
            reason: format!("Unexpected Token {:?}", token.category()),
            token: Some(token),
            position: None,
        }
    }

    pub fn unexpected_end(origin: &str) -> TokenError {
        TokenError {
            reason: format!("Unexpected end while {}", origin),
            token: None,
            position: None,
        }
    }
    pub fn unclosed(token: Token) -> TokenError {
        TokenError {
            reason: format!("Unclosed {:?}", token.category()),
            token: Some(token),
            position: None,
        }
    }

    fn missing_semicolon(token: Token, end: Option<Token>) -> TokenError {
        let position = if let Some(et) = end {
            Range {
                start: token.position.0,
                end: et.position.1,
            }
        } else {
            token.range()
        };
        TokenError {
            reason: format!("Missing semicolon {:?}", token.category()),
            token: Some(token),
            position: Some(position),
        }
    }
    fn position(&self) -> (usize, usize) {
        self.token.map(|t| t.position).unwrap_or((0, 0))
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn range(&self) -> Range<usize> {
        match self.position.clone() {
            Some(x) => x,
            None => {
                let (start, end) = self.position();
                Range { start, end }
            }
        }
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl Error for TokenError {}
