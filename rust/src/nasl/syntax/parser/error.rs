use std::fmt::Display;

use crate::nasl::{
    error::{AsCodespanError, Span, Spanned},
    syntax::{Keyword, TokenKind, TokenizerError, tokenizer::TokenizerErrorKind},
};

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct SpannedError {
    pub kind: ErrorKind,
    span: Span,
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Tokenizer(TokenizerErrorKind),
    TokensExpected(Vec<TokenKind>),
    TokenExpected(TokenKind),
    ExpressionExpected,
    EofExpected,
    UnexpectedKeyword(Keyword),
    IdentExpected,
    LiteralExpected,
    StringExpected,
    ExpectedAssignmentOperator,
    ExpectedUnaryOperator,
    ExpectedBinaryOperator,
    NotAllowedInPlaceExpr,
    InvalidDescriptionBlock(String),
}

impl Error {
    pub fn unwrap_as_spanned(self) -> SpannedError {
        SpannedError {
            kind: self.kind,
            span: self.span.unwrap(),
        }
    }

    /// Add the given span only if no span is present.
    pub fn with_span(self, span: &impl Spanned) -> Error {
        Self {
            kind: self.kind,
            span: Some(self.span.unwrap_or(span.span())),
        }
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
            ErrorKind::Tokenizer(e) => {
                write!(f, "Error during tokenization: {e}")
            }
            ErrorKind::ExpressionExpected => write!(f, "Expected expression"),
            ErrorKind::EofExpected => write!(f, "Expected end of file"),
            ErrorKind::UnexpectedKeyword(kw) => write!(f, "Unexpected keyword {kw:?}"),
            ErrorKind::IdentExpected => write!(f, "Expected identifier."),
            ErrorKind::LiteralExpected => write!(f, "Expected literal."),
            ErrorKind::StringExpected => {
                write!(f, "Expected string.")
            }
            ErrorKind::TokenExpected(token_kind) => write!(f, "Expected '{token_kind}'"),
            ErrorKind::TokensExpected(token_kinds) => write!(
                f,
                "Expected one of '{}'",
                token_kinds
                    .iter()
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
            ErrorKind::NotAllowedInPlaceExpr => {
                write!(f, "Not a valid assignment target.")
            }
            ErrorKind::InvalidDescriptionBlock(s) => {
                write!(f, "Invalid description block. {s}")
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
        self.span
    }

    fn message(&self) -> String {
        format!("{}", self.kind)
    }
}
