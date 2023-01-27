// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fmt::Display, io};

use nasl_syntax::{Statement, SyntaxError};
use sink::SinkError;

use crate::NaslValue;

#[derive(Debug)]
pub enum FunctionErrorKind {
    MissingPositionalArguments { expected: usize, got: usize },
    MissingArguments(Vec<String>),
    FMTError(String),
    WrongArgument(String),
    SinkError(SinkError),
    IOError(io::ErrorKind),
}

impl From<(&str, &str, &str)> for FunctionErrorKind {
    fn from(value: (&str, &str, &str)) -> Self {
        let (key, expected, got) = value;
        FunctionErrorKind::WrongArgument(format!("Expected {key} to be {expected} but it is {got}"))
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

impl From<(&str,  &NaslValue)> for FunctionErrorKind {
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

impl From<std::fmt::Error>  for FunctionErrorKind {
    fn from(fe: std::fmt::Error) -> Self {
        Self::FMTError(fe.to_string())
    }
}

impl From<io::ErrorKind> for FunctionErrorKind {
    fn from(iek: io::ErrorKind) -> Self {
        Self::IOError(iek)
    }
}

#[derive(Debug)]
pub struct FunctionError {
    pub function: String,
    pub kind: FunctionErrorKind,
}

impl FunctionError {
    pub fn new(function: String, kind: FunctionErrorKind) -> Self {
        Self { function, kind }
    }
}

impl From<SinkError> for FunctionError {
    fn from(e: SinkError) -> Self {
        Self::new("".to_owned(), e.into())
    }
}


#[derive(Debug, PartialEq, Eq)]
/// Is used to represent an error while interpreting
pub struct InterpretError {
    /// Represents a human readable reason
    pub reason: String,
    /// The line number within the script when that error occurred
    ///
    /// It starts 1.
    pub line: usize,
    /// The colum number within the script when that error occurred
    ///
    /// It starts 1.
    pub col: usize,
}

impl InterpretError {
    /// Creates a new Error with line and col set to 0
    ///
    /// Use this only when there is no statement available.
    /// If the line as well as col is null Interpreter::resolve will replace it
    /// with the line and col number based on the root statement.
    pub fn new(reason: String) -> Self {
        Self {
            reason,
            line: 0,
            col: 0,
        }
    }

    /// Creates a new Error based on a given statement and reason
    pub fn from_statement(stmt: &Statement, reason: String) -> Self {
        let (line, col) = stmt.as_token().map(|x| x.position).unwrap_or_default();
        InterpretError { reason, line, col }
    }

    /// Creates a new internal Error based on a given statement and dspl
    ///
    /// It produces the reason Internal error: statement {statement} -> {dspl}
    pub fn internal_error(stmt: &Statement, dspl: &dyn Display) -> Self {
        Self::from_statement(
            stmt,
            format!("Internal error: statement {} -> {}", stmt, dspl),
        )
    }

    /// Creates a InterpreterError for an unsupported statement
    ///
    /// It produces the reason {root}: {statement} is not supported
    pub fn unsupported(stmt: &Statement, root: &str) -> Self {
        Self::from_statement(stmt, format!("{}: {} is not supported", root, stmt))
    }
}

impl From<SyntaxError> for InterpretError {
    fn from(err: SyntaxError) -> Self {
        InterpretError {
            reason: err.to_string(),
            line: 0,
            col: 0,
        }
    }
}
