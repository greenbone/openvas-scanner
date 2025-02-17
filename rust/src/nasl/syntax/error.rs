// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines TokenError and its companion macros.

use std::io;

use thiserror::Error;

use crate::nasl::syntax::{token::Token, Statement};

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
}

/// Is used to express errors while parsing.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct SyntaxError {
    /// A human readable reason why this error is returned
    pub kind: ErrorKind,
    pub(crate) line: u32,
    pub(crate) file: String,
}

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
        }
    }
}

/// Creates an SyntaxError.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use scannerlib::nasl::syntax::{ErrorKind, Token, TokenCategory};
/// use scannerlib::syntax_error;
/// syntax_error!(
///     ErrorKind::UnexpectedToken(Token {
///         category: TokenCategory::UnknownSymbol,
///         line_column: (42, 42),
///         position: (42, 42),
///     })
/// );
/// ```
#[macro_export]
macro_rules! syntax_error {
    ($kind:expr) => {{
        use $crate::nasl::syntax::SyntaxError;
        SyntaxError::new($kind, line!(), file!().to_string())
    }};
}

/// Creates an unexpected Token error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use scannerlib::nasl::syntax::{Token, TokenCategory};
/// use scannerlib::unexpected_token;
/// unexpected_token!(Token {
///     category: TokenCategory::UnknownSymbol,
///     line_column: (42, 42),
///     position: (42, 42),
/// });
/// ```
#[macro_export]
macro_rules! unexpected_token {
    ($token:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;
        syntax_error!(ErrorKind::UnexpectedToken($token))
    }};
}

/// Creates an unexpected statement error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use scannerlib::nasl::syntax::{Statement, StatementKind};
/// use scannerlib::unexpected_statement;
/// unexpected_statement!(Statement::without_token(StatementKind::EoF));
/// ```
#[macro_export]
macro_rules! unexpected_statement {
    ($statement:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;
        syntax_error!(ErrorKind::MissingSemicolon($statement))
    }};
}

/// Creates an unexpected statement error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use scannerlib::nasl::syntax::{Statement, StatementKind};
/// use scannerlib::unclosed_statement;
/// unclosed_statement!(Statement::without_token(StatementKind::EoF));
/// ```
#[macro_export]
macro_rules! unclosed_statement {
    ($statement:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;

        syntax_error!(ErrorKind::UnclosedStatement($statement))
    }};
}

/// Creates an unclosed Token error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use scannerlib::nasl::syntax::{Token, TokenCategory};
/// use scannerlib::unclosed_token;
/// unclosed_token!(Token {
///     category: TokenCategory::UnknownSymbol,
///     position: (42, 42),
///     line_column: (42, 42),
/// });
/// ```
#[macro_export]
macro_rules! unclosed_token {
    ($token:expr) => {{
        use $crate::nasl::syntax::ErrorKind;
        use $crate::syntax_error;

        syntax_error!(ErrorKind::UnclosedToken($token))
    }};
}

/// Creates an unexpected end error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use scannerlib::unexpected_end;
/// unexpected_end!("within an example.");
/// ```
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
    /// Creates a new SyntaxError.
    pub fn new(kind: ErrorKind, line: u32, file: String) -> Self {
        Self { kind, line, file }
    }

    /// Returns the ErrorKind of SyntaxError
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<io::Error> for SyntaxError {
    fn from(initial: io::Error) -> Self {
        SyntaxError::new(
            ErrorKind::IOError(initial.kind()),
            line!(),
            file!().to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::syntax::{parse, ErrorKind, TokenCategory};

    fn test_for_missing_semicolon(code: &str) {
        let result = parse(code).next().unwrap();
        match result {
            Ok(_) => panic!("expected test to return Err for {code}"),
            Err(e) => match e.kind {
                ErrorKind::MissingSemicolon(_) => {}
                _ => panic!("Expected MissingSemicolon but got: {e:?}"),
            },
        }
    }

    fn test_for_unclosed_token(code: &str, category: TokenCategory) {
        let result = parse(code).next().unwrap();
        match result {
            Ok(_) => panic!("expected test to return Err"),
            Err(e) => match e.kind {
                ErrorKind::UnclosedToken(token) => {
                    assert_eq!(token.category(), &category);
                }
                _ => panic!("Expected UnclosedToken but got: {e:?} for {code}"),
            },
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
        test_for_unclosed_token("called(me;", TokenCategory::LeftParen);
        test_for_unclosed_token("foreach a(x { a = 2;", TokenCategory::LeftParen);
        test_for_unclosed_token("for (i = 0; i < 10; i++ ;", TokenCategory::LeftParen);
        test_for_unclosed_token("while (TRUE ;", TokenCategory::LeftParen);
    }

    #[test]
    fn missing_right_curly_bracket() {
        test_for_unclosed_token("if (a) { a = 2", TokenCategory::LeftCurlyBracket);
        test_for_unclosed_token("foreach a(x) { a = 2;", TokenCategory::LeftCurlyBracket);
        test_for_unclosed_token("{ a = 2;", TokenCategory::LeftCurlyBracket);
        test_for_unclosed_token("function a() { a = 2;", TokenCategory::LeftCurlyBracket);
    }
}
