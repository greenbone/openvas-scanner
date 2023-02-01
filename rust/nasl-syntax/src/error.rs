// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines TokenError and its companion macros.

use core::fmt;
use std::{error::Error, io};

use crate::{token::Token, Statement};

#[derive(Clone, Debug, PartialEq, Eq)]
/// A list specifying general categories of Syntax error.
pub enum ErrorKind {
    /// An unexpected token occurred
    UnexpectedToken(Token),
    /// A token is unclosed
    ///
    /// Could happen on string literals.
    UnclosedToken(Token),
    /// An unexpected statement occurred
    UnexpectedStatement(Statement),
    /// An token is unclosed
    UnclosedStatement(Statement),
    /// The cursor is already at the end but that is not expected
    EoF,
    /// An IO Error occurred while loading a NASL file
    IOError(io::ErrorKind),
}

/// Is used to express errors while parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    /// A human readable reason why this error is returned
    kind: ErrorKind,
    pub(crate) line: u32,
    pub(crate) file: String,
}

/// Creates an SyntaxError.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{syntax_error, ErrorKind, Token, TokenCategory};
/// syntax_error!(
///     ErrorKind::UnexpectedToken(Token {
///         category: TokenCategory::UnknownSymbol,
///         position: (42, 42),
///     })
/// );
/// ```
#[macro_export]
macro_rules! syntax_error {
    ($kind:expr) => {{
        use $crate::SyntaxError;
        SyntaxError::new($kind, line!(), file!().to_string())
    }};
}

/// Creates an unexpected Token error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{unexpected_token, Token, TokenCategory};
/// unexpected_token!(Token {
///     category: TokenCategory::UnknownSymbol,
///     position: (42, 42),
/// });
/// ```
#[macro_export]
macro_rules! unexpected_token {
    ($token:expr) => {{
        use $crate::syntax_error;
        use $crate::ErrorKind;
        syntax_error!(ErrorKind::UnexpectedToken($token))
    }};
}

/// Creates an unexpected statement error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{unexpected_statement, Statement};
/// unexpected_statement!(Statement::EoF);
/// ```
#[macro_export]
macro_rules! unexpected_statement {
    ($statement:expr) => {{
        use $crate::syntax_error;
        use $crate::ErrorKind;

        syntax_error!(ErrorKind::UnexpectedStatement($statement))
    }};
}

/// Creates an unexpected statement error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{unexpected_statement, Statement};
/// unexpected_statement!(Statement::EoF);
/// ```
#[macro_export]
macro_rules! unclosed_statement {
    ($statement:expr) => {{
        use $crate::syntax_error;
        use $crate::ErrorKind;

        syntax_error!(ErrorKind::UnclosedStatement($statement))
    }};
}

/// Creates an unclosed Token error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::{unclosed_token, Token, TokenCategory};
/// unclosed_token!(Token {
///     category: TokenCategory::UnknownSymbol,
///     position: (42, 42),
/// });
/// ```
#[macro_export]
macro_rules! unclosed_token {
    ($token:expr) => {{
        use $crate::syntax_error;
        use $crate::ErrorKind;

        syntax_error!(ErrorKind::UnclosedToken($token))
    }};
}

/// Creates an unexpected end error.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use nasl_syntax::unexpected_end;
/// unexpected_end!("within an example.");
/// ```
#[macro_export]
macro_rules! unexpected_end {
    ($reason:expr) => {{
        use $crate::syntax_error;
        use $crate::ErrorKind;
        syntax_error!(ErrorKind::EoF)
    }};
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::UnexpectedToken(token) => write!(f, "unexpected token: {:?}", token),
            ErrorKind::UnclosedToken(token) => write!(f, "unclosed token: {:?}", token),
            ErrorKind::UnexpectedStatement(stmt) => write!(f, "unexpected statement: {:?}", stmt),
            ErrorKind::UnclosedStatement(stmt) => write!(f, "unclosed statement: {:?}", stmt),
            ErrorKind::EoF => write!(f, "end of file."),
            ErrorKind::IOError(kind) => write!(f, "IOError: {}", kind),
        }
    }
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

impl Error for SyntaxError {}

impl From<io::Error> for SyntaxError {
    fn from(initial: io::Error) -> Self {
        SyntaxError::new(
            ErrorKind::IOError(initial.kind()),
            line!(),
            file!().to_owned(),
        )
    }
}
