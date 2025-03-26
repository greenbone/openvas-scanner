use std::fmt::Display;

use crate::nasl::{
    error::{AsCodespanError, Span},
    syntax::{Keyword, TokenKind, TokenizerError, tokenizer::TokenizerErrorKind},
};

#[derive(Debug)]
pub(super) struct Error {
    pub kind: ErrorKind,
    pub span: Option<Span>,
}

#[derive(Debug)]
pub struct SpannedError {
    pub kind: ErrorKind,
    pub span: Span,
}

#[derive(Debug)]
pub enum ErrorKind {
    TokensExpected(Vec<TokenKind>),
    TokenExpected(TokenKind),
    ExpressionExpected,
    EofExpected,
    UnexpectedKeyword(Keyword),
    IdentExpected,
    LiteralExpected,
    ExpectedAssignmentOperator,
    ExpectedUnaryOperator,
    ExpectedBinaryOperator,
    Tokenizer(TokenizerErrorKind),
}

impl Error {
    pub fn unwrap_as_spanned(self) -> SpannedError {
        SpannedError {
            kind: self.kind,
            span: self.span.unwrap(),
        }
    }

    /// Add the given span only if no span is present.
    pub fn add_span(self, span: Span) -> Error {
        Self {
            kind: self.kind,
            span: Some(self.span.unwrap_or(span)),
        }
    }
}

impl ErrorKind {
    pub fn to_error(self, span: Span) -> SpannedError {
        SpannedError { span, kind: self }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error { kind, span: None }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::ExpressionExpected => write!(f, "Expected expression"),
            ErrorKind::EofExpected => write!(f, "Expected end of file"),
            ErrorKind::UnexpectedKeyword(kw) => write!(f, "Unexpected keyword {kw:?}"),
            ErrorKind::IdentExpected => write!(f, "Expected identifier."),
            ErrorKind::LiteralExpected => write!(f, "Expected literal."),
            ErrorKind::TokenExpected(token_kind) => write!(f, "Expected '{}'", token_kind),
            ErrorKind::TokensExpected(token_kinds) => write!(
                f,
                "Expected one of '{}'",
                token_kinds
                    .into_iter()
                    .map(|k| k.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            ErrorKind::ExpectedAssignmentOperator => {
                write!(f, "Expected assignment operator (=, +=, -=, ...)")
            }
            ErrorKind::ExpectedUnaryOperator => {
                write!(f, "Expected unary operator (!, -)")
            }
            ErrorKind::ExpectedBinaryOperator => {
                write!(f, "Expected binary operator (+, -, *, /, ...)")
            }
            ErrorKind::Tokenizer(e) => {
                write!(f, "Error during tokenization: {e}")
            }
        }
    }
}

impl From<TokenizerError> for SpannedError {
    fn from(e: TokenizerError) -> Self {
        Self {
            kind: ErrorKind::Tokenizer(e.kind),
            span: e.span,
        }
    }
}

impl AsCodespanError for SpannedError {
    fn span(&self) -> Span {
        self.span.clone()
    }

    fn message(&self) -> String {
        self.kind.to_string()
    }
}
