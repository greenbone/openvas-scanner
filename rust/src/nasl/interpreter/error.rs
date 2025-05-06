// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::NaslValue;
use crate::nasl::code::SourceFile;
use crate::nasl::error::{AsCodespanError, Span, emit_errors};
use crate::nasl::syntax::ParseError;
use crate::nasl::syntax::grammar::Statement;
use crate::nasl::syntax::{Ident, LoadError, Token, TokenKind};
use crate::nasl::utils::error::FnError;
use thiserror::Error;

#[derive(Debug, Error)]
/// An error that occurred while calling a function
#[error("Error while calling function '{function}': {kind}")]
pub struct FunctionCallError {
    /// Name of the function
    pub function: String,
    /// Kind of error
    #[source]
    pub kind: FnError,
}

impl FunctionCallError {
    /// Creates a new FunctionError
    pub fn new(function: &str, kind: FnError) -> Self {
        Self {
            function: function.to_owned(),
            kind,
        }
    }

    fn retryable(&self) -> bool {
        self.kind.retryable()
    }
}

#[derive(Debug, Error)]
/// Is used to represent an error while interpreting
#[error("{} {kind}", self.format_origin())]
pub struct InterpretError {
    /// Defined the type of error that occurred.
    #[source]
    pub kind: InterpretErrorKind,
    // todo remove
    /// The statement on which this error occurred.
    pub origin: Option<Statement>,
    pub span: Span,
}

impl InterpretError {
    fn format_origin(&self) -> String {
        // TODO
        String::new()
    }

    pub fn retryable(&self) -> bool {
        match &self.kind {
            InterpretErrorKind::LoadError(LoadError::Retry(_)) => true,
            InterpretErrorKind::FunctionCallError(e) => e.retryable(),
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
/// Is used to give hints to the user how to react on an error while interpreting
pub enum InterpretErrorKind {
    /// When returned context is a function when a value is required.
    #[error("Expected a value but got a function.")]
    FunctionExpectedValue,
    /// When returned context is a value when a function is required.
    #[error("Expected a function but got a value.")]
    ValueExpectedFunction,
    /// When a specific type is expected
    #[error("Expected the type {0}")]
    WrongType(String),
    /// When a specific token kind is required but not given.
    #[error("Expected the kind {0}")]
    WrongCategory(TokenKind),
    /// Regex parsing went wrong.
    #[error("Invalid regular expression: {0}")]
    InvalidRegex(String),
    // TODO improve this error messages
    /// A SyntaxError while including another script
    #[error("{0}")]
    IncludeSyntaxError(IncludeSyntaxError),
    /// Syntax errors in the script.
    #[error("Syntax errors occured.")]
    SyntaxError(Vec<ParseError>),
    /// When the given key was not found in the context
    #[error("Key not found: {0}")]
    NotFound(String),
    /// A LoadError occurred
    #[error("{0}")]
    LoadError(LoadError),
    /// An error occurred while calling a built-in function.
    #[error("{0}")]
    FunctionCallError(FunctionCallError),
    /// A script tried to fork in a way that caused
    /// forks to run into different branches of
    /// the original statement which caused the fork.
    #[error(
        "Invalid fork. The interpreter forked in a position which was not reached by the created forks."
    )]
    InvalidFork,
    #[error("Expected a string.")]
    ExpectedString,
    #[error("Expected a boolean.")]
    ExpectedBoolean,
    #[error("Expected a number.")]
    ExpectedNumber,
    #[error("Expected an array.")]
    ExpectedArray,
    #[error("Expected a dict.")]
    ExpectedDict,
    #[error("Undefined variable: {0}")]
    UndefinedVariable(Ident),
    #[error("Assignment to undefined variable: {0}")]
    AssignmentToUndefinedVar(Ident),
    #[error("Array out of range for index: {0}")]
    ArrayOutOfRange(usize),
    #[error("Negative index into array: {0}")]
    NegativeIndex(i64),
    #[error("Dict key does not exist: {0}")]
    DictKeyDoesNotExist(String),
    #[error("Expected array or dict.")]
    ArrayOrDictExpected,
    #[error("Tried to exit with non-numeric exit code {0}.")]
    NonNumericExitCode(NaslValue),
}

// TODO fix this
impl From<InterpretErrorKind> for InterpretError {
    fn from(kind: InterpretErrorKind) -> Self {
        Self {
            kind,
            origin: None,
            span: Token::sentinel().span(),
        }
    }
}

#[derive(Debug)]
// TODO
pub struct IncludeSyntaxError {
    pub file: SourceFile,
    pub errs: Vec<ParseError>,
}

// TODO Get rid of this once we have a proper implementation of spans
// for InterpreterError as well.
impl std::fmt::Display for IncludeSyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        emit_errors(&self.file, self.errs.iter().cloned());
        write!(f, "Syntax error while including file.")
    }
}

impl InterpretError {
    /// Creates a new Error with line and col set to 0
    ///
    /// Use this only when there is no statement available.
    /// If the line as well as col is null Interpreter::resolve will replace it
    /// with the line and col number based on the root statement.
    // TODO: remove
    pub(crate) fn new(kind: InterpretErrorKind, origin: Option<Statement>) -> Self {
        Self {
            kind,
            origin,
            span: Token::sentinel().span(),
        }
    }

    pub(crate) fn new_temporary(kind: InterpretErrorKind, span: Span) -> Self {
        Self {
            kind,
            origin: Some(Statement::NoOp),
            span,
        }
    }

    // TODO: Remove
    /// Creates a new Error based on a given statement and reason
    pub(crate) fn from_statement(stmt: &Statement, kind: InterpretErrorKind) -> Self {
        Self::new(kind, Some(stmt.clone()))
    }

    /// Creates an InterpreterError if the found context is a value although a function is required
    pub(crate) fn expected_function() -> Self {
        Self::new(InterpretErrorKind::ValueExpectedFunction, None)
    }

    /// When something was not found
    pub(crate) fn not_found(name: &str) -> Self {
        Self::new(InterpretErrorKind::NotFound(name.to_owned()), None)
    }

    /// When a given regex is not parseable
    pub(crate) fn unparse_regex(rx: &str) -> Self {
        Self::new(InterpretErrorKind::InvalidRegex(rx.to_owned()), None)
    }
}

impl From<LoadError> for InterpretError {
    fn from(le: LoadError) -> Self {
        Self::new(InterpretErrorKind::LoadError(le), None)
    }
}

impl From<FunctionCallError> for InterpretError {
    fn from(fe: FunctionCallError) -> Self {
        Self::new(InterpretErrorKind::FunctionCallError(fe), None)
    }
}

impl AsCodespanError for InterpretError {
    fn span(&self) -> Span {
        self.span
    }

    fn message(&self) -> String {
        self.kind.to_string()
    }
}
