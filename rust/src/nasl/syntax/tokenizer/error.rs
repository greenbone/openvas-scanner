use thiserror::Error;

use crate::nasl::error::{AsCodespanError, Span};

#[derive(Clone, Debug)]
pub struct TokenizerError {
    pub kind: TokenizerErrorKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TokenizerErrorKind {
    #[error("Invalid number literal.")]
    InvalidNumberLiteral,
    #[error("Invalid IPv4 address.")]
    InvalidIpv4Address,
    #[error("Invalid character.")]
    InvalidCharacter,
    #[error("Unclosed string literal.")]
    UnclosedString,
    #[error("Unclosed data string literal.")]
    UnclosedData,
}

impl AsCodespanError for TokenizerError {
    fn span(&self) -> Span {
        self.span
    }

    fn message(&self) -> String {
        self.kind.to_string()
    }
}
