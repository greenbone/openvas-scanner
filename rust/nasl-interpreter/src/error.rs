// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::io;

use nasl_syntax::{Statement, SyntaxError, TokenCategory};
use sink::SinkError;

use crate::{ContextType, LoadError, NaslValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionErrorKind {
    MissingPositionalArguments { expected: usize, got: usize },
    MissingArguments(Vec<String>),
    FMTError(std::fmt::Error),
    SinkError(SinkError),
    IOError(io::ErrorKind),
    WrongArgument(String),
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

impl From<SinkError> for FunctionErrorKind {
    fn from(se: SinkError) -> Self {
        Self::SinkError(se)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionError {
    pub function: String,
    pub kind: FunctionErrorKind,
}

impl FunctionError {
    pub fn new(function: &str, kind: FunctionErrorKind) -> Self {
        Self {
            function: function.to_owned(),
            kind,
        }
    }
}

impl From<SinkError> for FunctionError {
    fn from(e: SinkError) -> Self {
        Self::new("", e.into())
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
    /// A SinkError occurred
    SinkError(SinkError),
    /// A SinkError occurred
    LoadError(LoadError),
    /// A Formatting error occurred
    FMTError(std::fmt::Error),
    /// An IOError occurred
    IOError(io::ErrorKind),
    /// An error occurred while calling a built-in function.
    FunctionCallError(FunctionError),
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

impl From<SinkError> for InterpretError {
    fn from(se: SinkError) -> Self {
        Self::new(InterpretErrorKind::SinkError(se), None)
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
            FunctionErrorKind::SinkError(se) => se.into(),
            FunctionErrorKind::IOError(ie) => ie.into(),
            _ => Self::new(InterpretErrorKind::FunctionCallError(fe), None),
        }
    }
}
