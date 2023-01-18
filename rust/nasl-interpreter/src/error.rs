use std::fmt::Display;

use nasl_syntax::{Statement, SyntaxError};

// TODO refactor error handling
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
pub struct InterpretError {
    pub reason: String,
    pub line: usize,
    pub col: usize,
}

impl InterpretError {
    pub fn new(reason: String) -> Self {
        Self {
            reason,
            line: 0,
            col: 0,
        }
    }

    pub fn from_statement(stmt: &Statement, reason: String) -> Self {
        let (line, col) = stmt.as_token().map(|x| x.position).unwrap_or_default();
        InterpretError { reason, line, col }
    }

    pub fn internal_error(stmt: &Statement, dspl: &dyn Display) -> Self {
        Self::from_statement(stmt, format!("Internal error: statement {} -> {}", stmt, dspl))
    }

    /// Creates a InterpreterError for an unsupported statement
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
