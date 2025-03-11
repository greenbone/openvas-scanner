use std::{fmt::Display, ops::Range};

use crate::nasl::error::AsCodespanError;

#[derive(Debug)]
pub struct TokenizerError {
    pub kind: TokenizerErrorKind,
    pub range: Range<usize>,
}

#[derive(Debug)]
pub enum TokenizerErrorKind {
    UnexpectedToken,
    UnterminatedStringLiteral,
    WrongNumberLiteral(String),
}

impl Display for TokenizerErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenizerErrorKind::UnexpectedToken => write!(f, "Unexpected token."),
            TokenizerErrorKind::UnterminatedStringLiteral => {
                write!(f, "Unterminated string literal.")
            }
            TokenizerErrorKind::WrongNumberLiteral(e) => {
                write!(f, "Failed to parse number literal. {e}")
            }
        }
    }
}

impl AsCodespanError for TokenizerError {
    fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    fn message(&self) -> String {
        self.kind.to_string()
    }
}
