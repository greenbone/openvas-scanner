use std::{fmt::Display, ops::Range};

use crate::nasl::{
    error::AsCodespanError,
    syntax::{Keyword, TokenKind, TokenizerError, tokenizer::TokenizerErrorKind},
};

#[derive(Debug)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub range: Range<usize>,
}

impl ParseErrorKind {
    pub fn to_error(self, range: Range<usize>) -> ParseError {
        ParseError { range, kind: self }
    }
}

#[derive(Debug)]
pub enum ParseErrorKind {
    TokenExpected(TokenKind),
    ExpressionExpected,
    EofExpected,
    UnexpectedKeyword(Keyword),
    IdentExpected,
    ExpectedAssignmentOperator,
    ExpectedUnaryOperator,
    ExpectedBinaryOperator,
    Tokenizer(TokenizerErrorKind),
}

impl Display for ParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseErrorKind::ExpressionExpected => write!(f, "Expected expression"),
            ParseErrorKind::EofExpected => write!(f, "Expected end of file"),
            ParseErrorKind::UnexpectedKeyword(kw) => write!(f, "Unexpected keyword {kw:?}"),
            ParseErrorKind::IdentExpected => write!(f, "Expected identifier."),
            ParseErrorKind::TokenExpected(token_kind) => write!(f, "Expected '{}'", token_kind),
            ParseErrorKind::ExpectedAssignmentOperator => {
                write!(f, "Expected assignment operator (=, +=, -=, ...)")
            }
            ParseErrorKind::ExpectedUnaryOperator => {
                write!(f, "Expected unary operator (!, -)")
            }
            ParseErrorKind::ExpectedBinaryOperator => {
                write!(f, "Expected binary operator (+, -, *, /, ...)")
            }
            ParseErrorKind::Tokenizer(e) => {
                write!(f, "Error during tokenization: {e}")
            }
        }
    }
}

impl From<TokenizerError> for ParseError {
    fn from(e: TokenizerError) -> Self {
        Self {
            kind: ParseErrorKind::Tokenizer(e.kind),
            range: e.range,
        }
    }
}

impl AsCodespanError for ParseError {
    fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    fn message(&self) -> String {
        self.kind.to_string()
    }
}
