// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines TokenError and its companion macros.

use std::{io, ops::Range};

use thiserror::Error;

use crate::nasl::{
    error::AsCodespanError,
    syntax::{token::Token, Statement},
};

use super::{tokenizer::TokenizerErrorKind, TokenizerError};

#[derive(Clone, Debug, PartialEq, Eq, Error)]
/// A list specifying general categories of Syntax error.
pub enum ErrorKind {
    /// An unexpected token occurred
    #[error("Unexpected token: {0}")]
    UnexpectedToken(Token),
    /// A token is unclosed
    ///
    /// Could happen on string literals.
    #[error("Unclosed token: {0}")]
    UnclosedToken(Token),
    /// An unexpected statement occurred
    #[error("Unexpected statement: {0}")]
    UnexpectedStatement(Statement),
    /// When an unexpected Statement occurs it maybe an MissingSemicolon
    #[error("Missing semicolon: {0}")]
    MissingSemicolon(Statement),
    /// An token is unclosed
    #[error("Unclosed statement: {0}")]
    UnclosedStatement(Statement),
    /// Maximal recursion depth reached. Simplify NASL code.
    #[error("Maximal recursion depth of {0} reached, the NASL script is too complex.")]
    MaxRecursionDepth(u8),
    /// The cursor is already at the end but that is not expected
    #[error("Unexpected end of file.")]
    EoF,
    /// An IO Error occurred while loading a NASL file
    #[error("IOError: {0}")]
    IOError(io::ErrorKind),
    #[error("{0}")]
    Tokenizer(#[from] TokenizerErrorKind),
}

impl From<TokenizerError> for SyntaxError {
    fn from(value: TokenizerError) -> Self {
        Self {
            kind: ErrorKind::Tokenizer(value.kind),
            range: value.range,
        }
    }
}

/// Is used to express errors while parsing.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct SyntaxError {
    /// A human readable reason why this error is returned
    pub kind: ErrorKind,
    pub range: Range<usize>,
}

// TODO Remove this
impl SyntaxError {
    /// Returns a token of the underlying error kind
    pub fn as_token(&self) -> Option<&Token> {
        match &self.kind {
            ErrorKind::UnexpectedToken(t) => Some(t),
            ErrorKind::UnclosedToken(t) => Some(t),
            ErrorKind::UnexpectedStatement(s) => Some(s.as_token()),
            ErrorKind::MissingSemicolon(s) => Some(s.as_token()),
            ErrorKind::UnclosedStatement(s) => Some(s.as_token()),
            ErrorKind::EoF => None,
            ErrorKind::IOError(_) => None,
            ErrorKind::MaxRecursionDepth(_) => None,
            ErrorKind::Tokenizer(_) => None,
        }
    }
}

#[macro_export]
macro_rules! syntax_error {
    ($kind:expr) => {{
        use $crate::nasl::syntax::SyntaxError;
        // TODO
        SyntaxError {
            kind: $kind,
            range: 0..0,
        }
    }};
}

#[macro_export]
macro_rules! unexpected_token {
    ($token:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;
        syntax_error!(ErrorKind::UnexpectedToken($token))
    }};
}

#[macro_export]
macro_rules! unexpected_statement {
    ($statement:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;
        syntax_error!(ErrorKind::MissingSemicolon($statement))
    }};
}

#[macro_export]
macro_rules! unclosed_statement {
    ($statement:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;

        syntax_error!(ErrorKind::UnclosedStatement($statement))
    }};
}

#[macro_export]
macro_rules! unclosed_token {
    ($token:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;

        syntax_error!(ErrorKind::UnclosedToken($token))
    }};
}

#[macro_export]
macro_rules! unexpected_end {
    ($reason:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;
        syntax_error!(ErrorKind::EoF)
    }};
}

/// Creates an maximal recursion depth reached error.
///
/// To prevent stack overflows the Lexer veriefies it's depth and returns an error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use scannerlib::max_recursion;
/// max_recursion!(255);
/// ```
#[macro_export]
macro_rules! max_recursion {
    ($reason:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;
        syntax_error!(ErrorKind::MaxRecursionDepth($reason))
    }};
}

impl SyntaxError {
    /// Returns the ErrorKind of SyntaxError
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl AsCodespanError for SyntaxError {
    fn range(&self) -> std::ops::Range<usize> {
        self.range.clone()
    }

    fn message(&self) -> String {
        format!("{}", self.kind)
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::syntax::{parse_only_first_error, ErrorKind, TokenKind};

    fn test_for_missing_semicolon(code: &str) {
        let err = parse_only_first_error(code).unwrap_err();
        match err.kind {
            ErrorKind::MissingSemicolon(_) => {}
            _ => panic!("Expected MissingSemicolon but got: {err:?}"),
        }
    }

    fn test_for_unclosed_token(code: &str, kind: TokenKind) {
        let err = parse_only_first_error(code).unwrap_err();
        match err.kind {
            ErrorKind::UnclosedToken(token) => {
                assert_eq!(token.kind(), &kind);
            }
            _ => panic!("Expected UnclosedToken but got: {err:?} for {code}"),
        }
    }
    #[test]
    fn missing_semicolon_assignment() {
        let code = "a = 12";
        test_for_missing_semicolon(code);
        let code = "a = [1, 2, 4]";
        test_for_missing_semicolon(code);
    }

    #[test]
    fn missing_semicolon_call() {
        let code = "called(me)";
        test_for_missing_semicolon(code);
    }

    #[test]
    fn missing_right_paren() {
        test_for_unclosed_token("called(me;", TokenKind::LeftParen);
        test_for_unclosed_token("foreach a(x { a = 2;", TokenKind::LeftParen);
        test_for_unclosed_token("for (i = 0; i < 10; i++ ;", TokenKind::LeftParen);
        test_for_unclosed_token("while (TRUE ;", TokenKind::LeftParen);
    }

    #[test]
    fn missing_right_curly_bracket() {
        test_for_unclosed_token("if (a) { a = 2", TokenKind::LeftCurlyBracket);
        test_for_unclosed_token("foreach a(x) { a = 2;", TokenKind::LeftCurlyBracket);
        test_for_unclosed_token("{ a = 2;", TokenKind::LeftCurlyBracket);
        test_for_unclosed_token("function a() { a = 2;", TokenKind::LeftCurlyBracket);
    }
}
