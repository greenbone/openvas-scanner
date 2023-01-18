use std::fmt::Display;

use nasl_syntax::{Statement, SyntaxError};

#[derive(Debug)]
pub struct FunctionError {
    pub reason: String,
}

impl FunctionError {
    pub fn new(reason: String) -> Self {
        Self { reason }
    }
}

#[derive(Debug, PartialEq, Eq)]
/// Is used to represent an error while interpreting
pub struct InterpretError {
    /// Represents a human readable reason
    pub reason: String,
    /// The line number within the script when that error occured
    ///
    /// It starts 1.
    pub line: usize,
    /// The colum number within the script when that error occured
    ///
    /// It starts 1.
    pub col: usize,
}

impl InterpretError {
    /// Creates a new Error with line and col set to 0
    ///
    /// Use this only when there is no statement available.
    /// If thre line as well as col is null Interpreter::resolve will replace it 
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
