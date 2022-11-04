use core::fmt;
use std::{error::Error, ops::Range, usize};

use crate::{
    operator_precedence_parser,
    token::{Category, Keyword, Token, Tokenizer},
};

/// Is used to lookup block specific data like variables and functions.
/// The first number is the parent while the second is the own.
type BlockDepth = (u8, u8);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    RawNumber(u8),
    Primitive(Token),
    Variable(Token),
    Call(Token, Box<Statement>),
    Parameter(Vec<Statement>),
    Expanded(Box<Statement>, Box<Statement>), // e.g. on i++ it gets expanded to Statement, Assign(Variable, Operator(+, ...))
    Assign(Token, Box<Statement>),
    AssignReturn(Token, Box<Statement>), // e.g. ++i or (i = i + 1)

    Operator(Category, Vec<Statement>),

    If(Box<Statement>, Box<Statement>, Option<Box<Statement>>),
    Block(Vec<Statement>),
    NoOp(Option<Token>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variable<'a> {
    name: &'a str,
    token: &'a Token,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Functions {}

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

