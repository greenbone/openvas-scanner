use codespan_reporting::diagnostic::Diagnostic;
use thiserror::Error;

use crate::nasl::error::{IntoDiagnostic, Span, basic_error_diagnostic};

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

impl IntoDiagnostic for TokenizerError {
    fn into_diagnostic(self) -> Diagnostic<()> {
        basic_error_diagnostic(self.kind.to_string(), self.span)
    }
}
