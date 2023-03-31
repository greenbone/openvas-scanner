// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{convert::Infallible, fmt::Display, io};

use aes::cipher::block_padding::UnpadError;
use nasl_syntax::{Statement, SyntaxError, TokenCategory};
use storage::StorageError;

use crate::{ContextType, LoadError, NaslValue};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Describtive kinds of cryptographic errors
pub enum CryptErrorKind {
    /// Unpadding error
    Unpad,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Describtive kind of error that can occur while calling a function
pub enum FunctionErrorKind {
    /// Function called with insufficient arguments
    MissingPositionalArguments {
        /// Expected amount of arguments
        expected: usize,
        /// Actual amount of arguments
        got: usize,
    },
    /// Function called without required named arguments
    MissingArguments(Vec<String>),
    /// Wraps formatting error
    FMTError(std::fmt::Error),
    /// Wraps StorageError
    StorageError(StorageError),
    /// Wraps Infallible
    Infallible(Infallible),
    /// Wraps io::ErrorKind
    IOError(io::ErrorKind),
    /// Function was called with wrong arguments
    WrongArgument(String),
    /// Diagnostic string is informational and the second arg is the return value for the user
    Diagnostic(String, Option<NaslValue>),
    /// Generic error
    GeneralError(String),
    /// An error occurred while doing a crypt operation
    CryptError(CryptErrorKind),
}

impl Display for FunctionErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FunctionErrorKind::MissingPositionalArguments { expected, got } => {
                write!(f, "expected {expected} arguments but got {got}")
            }
            FunctionErrorKind::MissingArguments(x) => {
                write!(f, "missing arguments: {}", x.join(", "))
            }
            FunctionErrorKind::FMTError(e) => write!(f, "{e}"),
            FunctionErrorKind::StorageError(e) => write!(f, "{e}"),
            FunctionErrorKind::Infallible(e) => write!(f, "{e}"),
            FunctionErrorKind::IOError(e) => write!(f, "{e}"),
            FunctionErrorKind::WrongArgument(x) => write!(f, "wrong argument: {x}"),
            FunctionErrorKind::Diagnostic(x, _) => write!(f, "{x}"),
            FunctionErrorKind::GeneralError(x) => write!(f, "{x}"),
            FunctionErrorKind::CryptError(e) => write!(f, "cryptographic error: {e:?}"),
        }
    }
}

impl From<UnpadError> for FunctionErrorKind {
    fn from(_: UnpadError) -> Self {
        FunctionErrorKind::CryptError(CryptErrorKind::Unpad)
    }
}

impl From<(&str, &str, &str)> for FunctionErrorKind {
    fn from(value: (&str, &str, &str)) -> Self {
        let (key, expected, got) = value;
        FunctionErrorKind::WrongArgument(format!("Expected {key} to be {expected} but it is {got}"))
    }
}

impl From<&str> for FunctionErrorKind {
    fn from(value: &str) -> Self {
        FunctionErrorKind::MissingArguments(vec![value.to_owned()])
    }
}

impl From<(&str, &str)> for FunctionErrorKind {
    fn from(value: (&str, &str)) -> Self {
        let (expected, got) = value;
        FunctionErrorKind::WrongArgument(format!("Expected {expected} but got {got}"))
    }
}

impl From<(&str, &str, &NaslValue)> for FunctionErrorKind {
    fn from(value: (&str, &str, &NaslValue)) -> Self {
        let (key, expected, got) = value;
        let got: &str = &got.to_string();
        (key, expected, got).into()
    }
}

impl From<(&str, &str, Option<&NaslValue>)> for FunctionErrorKind {
    fn from(value: (&str, &str, Option<&NaslValue>)) -> Self {
        match value {
            (key, expected, Some(x)) => (key, expected, x).into(),
            (key, expected, None) => (key, expected, "NULL").into(),
        }
    }
}

impl From<(&str, &str, Option<&ContextType>)> for FunctionErrorKind {
    fn from(value: (&str, &str, Option<&ContextType>)) -> Self {
        match value {
            (key, expected, Some(ContextType::Value(x))) => (key, expected, x).into(),
            (key, expected, Some(ContextType::Function(_, _))) => {
                (key, expected, "function").into()
            }
            (key, expected, None) => (key, expected, "NULL").into(),
        }
    }
}
impl From<(&str, &NaslValue)> for FunctionErrorKind {
    fn from(value: (&str, &NaslValue)) -> Self {
        let (expected, got) = value;
        let got: &str = &got.to_string();
        (expected, got).into()
    }
}

impl From<StorageError> for FunctionErrorKind {
    fn from(se: StorageError) -> Self {
        Self::StorageError(se)
    }
}

impl From<Infallible> for FunctionErrorKind {
    fn from(se: Infallible) -> Self {
        Self::Infallible(se)
    }
}

impl From<std::fmt::Error> for FunctionErrorKind {
    fn from(fe: std::fmt::Error) -> Self {
        Self::FMTError(fe)
    }
}

impl From<io::ErrorKind> for FunctionErrorKind {
    fn from(iek: io::ErrorKind) -> Self {
        Self::IOError(iek)
    }
}

impl From<io::Error> for FunctionErrorKind {
    fn from(e: io::Error) -> Self {
        Self::IOError(e.kind())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// An error that occurred while calling a function
pub struct FunctionError {
    /// Name of the function
    pub function: String,
    /// Kind of error
    pub kind: FunctionErrorKind,
}

impl FunctionError {
    /// Creates a new FunctionError
    pub fn new(function: &str, kind: FunctionErrorKind) -> Self {
        Self {
            function: function.to_owned(),
            kind,
        }
    }
}

impl Display for FunctionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.function, self.kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Is used to represent an error while interpreting
pub struct InterpretError {
    /// Defined the type of error that occurred.
    pub kind: InterpretErrorKind,
    /// The statement on which this error occurred.
    pub origin: Option<Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Is used to give hints to the user how to react on an error while interpreting
pub enum InterpretErrorKind {
    /// When returned context is a function when a value is required.
    FunctioExpectedValue,
    /// When returned context is a value when a function is required.
    ValueExpectedFunction,
    /// When a specific type is expected
    WrongType(String),
    /// When a specific token category is required but not given.
    WrongCategory(TokenCategory),
    /// Regex parsing went wrong.
    InvalidRegex(String),
    /// An SyntaxError while including another script
    IncludeSyntaxError {
        /// The name of the file trying to include
        filename: String,
        /// The syntactical error that occurred
        err: SyntaxError,
    },
    /// SyntaxError
    SyntaxError(SyntaxError),
    /// When the given key was not found in the context
    NotFound(String),
    /// A StorageError occurred
    StorageError(StorageError),
    /// A LoadError occurred
    LoadError(LoadError),
    /// A Formatting error occurred
    FMTError(std::fmt::Error),
    /// An IOError occurred
    IOError(io::ErrorKind),
    /// An error occurred while calling a built-in function.
    FunctionCallError(FunctionError),
}

impl Display for InterpretErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterpretErrorKind::FunctioExpectedValue => {
                write!(f, "expected a value but got a function")
            }
            InterpretErrorKind::ValueExpectedFunction => {
                write!(f, "expected a function but got a value")
            }
            InterpretErrorKind::WrongType(e) => write!(f, "expected the type {e}"),
            InterpretErrorKind::WrongCategory(e) => write!(f, "expecteced category {e}"),
            InterpretErrorKind::InvalidRegex(e) => write!(f, "regular expression: {e} is invalid"),
            InterpretErrorKind::IncludeSyntaxError { filename, err } => {
                write!(
                    f,
                    "on include {filename}{}: {err}",
                    err.as_token()
                        .map(|t| format!(", line: {}, col: {}", t.position.0, t.position.1))
                        .unwrap_or_default()
                )
            }
            InterpretErrorKind::SyntaxError(e) => write!(f, "{e}"),
            InterpretErrorKind::NotFound(e) => write!(f, "{e} not found"),
            InterpretErrorKind::StorageError(e) => write!(f, "{e}"),
            InterpretErrorKind::LoadError(e) => write!(f, "{e}"),
            InterpretErrorKind::FMTError(e) => write!(f, "{e}"),
            InterpretErrorKind::IOError(e) => write!(f, "{e}"),
            InterpretErrorKind::FunctionCallError(e) => write!(f, "{e}"),
        }
    }
}

impl Display for InterpretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            self.origin
                .clone()
                .map(|e| format!("{e}: "))
                .unwrap_or_default(),
            self.kind
        )
    }
}

impl InterpretError {
    /// Creates a new Error with line and col set to 0
    ///
    /// Use this only when there is no statement available.
    /// If the line as well as col is null Interpreter::resolve will replace it
    /// with the line and col number based on the root statement.
    pub fn new(kind: InterpretErrorKind, origin: Option<Statement>) -> Self {
        Self { kind, origin }
    }

    /// Creates a new Error based on a given statement and reason
    pub fn from_statement(stmt: &Statement, kind: InterpretErrorKind) -> Self {
        InterpretError {
            kind,
            origin: Some(stmt.clone()),
        }
    }

    /// Returns the column number
    pub fn column(&self) -> usize {
        let (_, col) = self.line_column();
        col
    }

    /// Returns the line number
    pub fn line(&self) -> usize {
        let (line, _) = self.line_column();
        line
    }

    /// Returns the line and column number
    ///
    /// Based on the stored statement the line and column number are retained.
    /// That start both at 1 the only occurrence when there is no such number is when either
    /// no statement is stored in this error or when the given statement is either a
    /// - Statement::EoF,
    /// - Statement::AttackCategory,
    /// - Statement::Continue,
    /// - Statement::Break
    ///
    /// On resolve of an interpreter that should be an map_err adding a origin when there is none so the
    /// case of returning 0,0 is in most cases a bug.
    pub fn line_column(&self) -> (usize, usize) {
        self.origin
            .as_ref()
            .and_then(|stmt| stmt.as_token())
            .map(|x| x.position)
            .unwrap_or_default()
    }

    /// Creates a InterpreterError for an unsupported statement
    ///
    /// It produces the reason {root}: {statement} is not supported
    pub fn unsupported(stmt: &Statement, expected: &str) -> Self {
        Self::from_statement(stmt, InterpretErrorKind::WrongType(expected.to_string()))
    }

    /// Creates an InterpreterError if the found context is a function although a value is required
    pub fn expected_value() -> Self {
        Self::new(InterpretErrorKind::FunctioExpectedValue, None)
    }

    /// Creates an InterpreterError if the found context is a value although a function is required
    pub fn expected_function() -> Self {
        Self::new(InterpretErrorKind::ValueExpectedFunction, None)
    }

    /// Creates an error if the TokenCategory is wrong
    pub fn wrong_category(cat: &TokenCategory) -> Self {
        Self::new(InterpretErrorKind::WrongCategory(cat.clone()), None)
    }

    /// When something was not found
    pub fn not_found(name: &str) -> Self {
        Self::new(InterpretErrorKind::NotFound(name.to_owned()), None)
    }

    /// When a include file has syntactical errors
    pub fn include_syntax_error(file: &str, se: SyntaxError) -> Self {
        Self::new(
            InterpretErrorKind::IncludeSyntaxError {
                filename: file.to_owned(),
                err: se,
            },
            None,
        )
    }
    /// When a given regex is not parseable
    pub fn unparse_regex(rx: &str) -> Self {
        Self::new(InterpretErrorKind::InvalidRegex(rx.to_owned()), None)
    }
}

impl From<SyntaxError> for InterpretError {
    fn from(err: SyntaxError) -> Self {
        Self::new(InterpretErrorKind::SyntaxError(err), None)
    }
}

impl From<StorageError> for InterpretError {
    fn from(se: StorageError) -> Self {
        Self::new(InterpretErrorKind::StorageError(se), None)
    }
}

impl From<io::ErrorKind> for InterpretError {
    fn from(ie: io::ErrorKind) -> Self {
        Self::new(InterpretErrorKind::IOError(ie), None)
    }
}

impl From<io::Error> for InterpretError {
    fn from(e: io::Error) -> Self {
        e.kind().into()
    }
}

impl From<std::fmt::Error> for InterpretError {
    fn from(fe: std::fmt::Error) -> Self {
        Self::new(InterpretErrorKind::FMTError(fe), None)
    }
}

impl From<LoadError> for InterpretError {
    fn from(le: LoadError) -> Self {
        Self::new(InterpretErrorKind::LoadError(le), None)
    }
}

impl From<FunctionError> for InterpretError {
    fn from(fe: FunctionError) -> Self {
        match fe.kind {
            FunctionErrorKind::FMTError(fe) => fe.into(),
            FunctionErrorKind::StorageError(se) => se.into(),
            FunctionErrorKind::IOError(ie) => ie.into(),
            _ => Self::new(InterpretErrorKind::FunctionCallError(fe), None),
        }
    }
}
