use core::fmt;
use std::{ops::Range, error::Error};

use crate::token::{Token, Category, Tokenizer};


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    Primitive(Token),
    Variable(Token),
    Call(Token, Box<Statement>), // TODO maybe box
    Parameter(Vec<Statement>),

    Operator(Category, Vec<Statement>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenError {
    reason: String,
    token: Option<Token>,
}

impl TokenError {
    pub fn unexpected_token(token: Token) -> TokenError {
        TokenError { reason: format!("Unexpected Token {:?}", token.category()), token: Some(token)}
    }

    pub fn unexpected_end(origin: &str) -> TokenError {
        TokenError { reason: format!("Unexpected end while {}", origin), token: None }
    }
    pub fn unclosed(token: Token) -> TokenError {
        TokenError { reason: format!("Unclosed {:?}", token.category()), token: Some(token )}
    }

    pub fn position(&self) -> (usize, usize) {
        self.token.map(|t|t.position).unwrap_or((0, 0))
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn range(&self) -> Range<usize> {
        let (start, end) = self.position();
        Range{
            start, end
        }
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl Error for TokenError {

}

struct Lexer<'a> {
    tokenizer: &'a mut Tokenizer<'a>,

}


