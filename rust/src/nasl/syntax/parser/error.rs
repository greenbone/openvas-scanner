use std::{fmt::Display, ops::Range};

use crate::nasl::{
    error::AsCodespanError,
    syntax::{Keyword, TokenKind},
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
    ClosingParenExpected,
    SemicolonExpected,
    ExpressionExpected,
    EofExpected,
    EqualsExpected,
    UnexpectedKeyword(Keyword),
    UnexpectedToken(TokenKind),
}

impl Display for ParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseErrorKind::ClosingParenExpected => write!(f, "Expected closing parenthesis"),
            ParseErrorKind::SemicolonExpected => write!(f, "Expected semicolon"),
            ParseErrorKind::ExpressionExpected => write!(f, "Expected expression"),
            ParseErrorKind::EofExpected => write!(f, "Expected end of file"),
            ParseErrorKind::EqualsExpected => write!(f, "Expected '='"),
            ParseErrorKind::UnexpectedKeyword(kw) => write!(f, "Unexpected keyword {kw:?}"),
            ParseErrorKind::UnexpectedToken(kind) => write!(f, "Unexpected token {kind:?}"),
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
