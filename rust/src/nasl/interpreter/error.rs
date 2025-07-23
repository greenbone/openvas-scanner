// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::NaslValue;
use crate::nasl::code::SourceFile;
use crate::nasl::error::{AsCodespanError, Level, Span, Spanned, emit_errors};
use crate::nasl::syntax::grammar::Expr;
use crate::nasl::syntax::{CharIndex, ParseError};
use crate::nasl::syntax::{Ident, LoadError};
use crate::nasl::utils::error::FnError;
use codespan_reporting::files::SimpleFile;
use thiserror::Error;

#[derive(Debug, Error)]
/// An error that occurred while calling a function
#[error("Error while calling function '{function}': {kind}")]
pub struct FunctionCallError {
    /// Name of the function
    function: String,
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
}

#[derive(Debug, Error)]
/// Is used to represent an error while interpreting
#[error("{} {kind}", self.format_origin())]
pub struct InterpreterError {
    /// The kind of error that occurred.
    #[source]
    pub kind: InterpreterErrorKind,
    span: Span,
}

impl InterpreterError {
    fn format_origin(&self) -> String {
        // TODO
        String::new()
    }
}

#[derive(Debug, Error)]
/// Is used to give hints to the user how to react on an error while interpreting
pub enum InterpreterErrorKind {
    /// When returned context is a function when a value is required.
    #[error("Expected a value but got a function.")]
    FunctionExpectedValue,
    /// When returned context is a value when a function is required.
    #[error("Expected a function but got a value.")]
    ValueExpectedFunction,
    /// Regex parsing went wrong.
    #[error("Invalid regular expression: {0}")]
    InvalidRegex(String),
    /// A SyntaxError while including another script
    #[error("{0}")]
    IncludeSyntaxError(IncludeSyntaxError),
    /// Syntax errors in the script.
    #[error("Syntax errors occurred.")]
    SyntaxError(Vec<ParseError>),
    /// When the given function is undefined.
    #[error("Undefined function: {0}")]
    UndefinedFunction(String),
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
    #[error("Expected a number.")]
    ExpectedNumber,
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

impl InterpreterErrorKind {
    pub(crate) fn with_span(self, s: &impl Spanned) -> InterpreterError {
        InterpreterError {
            kind: self,
            span: s.span(),
        }
    }
}

impl InterpreterError {
    pub(crate) fn syntax_error(errs: Vec<ParseError>) -> Self {
        Self {
            // fake value since we don't need the span in this case
            span: Span::new(CharIndex(usize::MAX - 1), CharIndex(usize::MAX)),
            kind: InterpreterErrorKind::SyntaxError(errs),
        }
    }

    pub(crate) fn include_syntax_error(
        errs: Vec<ParseError>,
        file: SimpleFile<String, String>,
    ) -> Self {
        Self {
            // fake value since we don't need the span in this case
            span: Span::new(CharIndex(usize::MAX - 1), CharIndex(usize::MAX)),
            kind: InterpreterErrorKind::IncludeSyntaxError(IncludeSyntaxError { errs, file }),
        }
    }
}

#[derive(Debug)]
// TODO
pub struct IncludeSyntaxError {
    file: SourceFile,
    errs: Vec<ParseError>,
}

// TODO Get rid of this once we have a proper implementation of spans
// for InterpreterError as well.
impl std::fmt::Display for IncludeSyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        emit_errors(&self.file, self.errs.iter().cloned(), Level::Error);
        write!(f, "Syntax error while including file.")
    }
}

impl InterpreterError {
    pub(crate) fn new(kind: InterpreterErrorKind, span: Span) -> Self {
        Self { kind, span }
    }
}

impl AsCodespanError for &InterpreterError {
    fn span(&self) -> Span {
        self.span
    }

    fn message(&self) -> String {
        self.kind.to_string()
    }
}

pub(super) struct ExprError {
    pub kind: InterpreterErrorKind,
    pub location: ExprLocation,
}

pub(super) enum ExprLocation {
    Lhs,
    Rhs,
    Both,
}

impl ExprError {
    pub fn lhs(kind: InterpreterErrorKind) -> Self {
        Self {
            kind,
            location: ExprLocation::Lhs,
        }
    }

    pub fn rhs(kind: InterpreterErrorKind) -> Self {
        Self {
            kind,
            location: ExprLocation::Rhs,
        }
    }

    pub fn both(kind: InterpreterErrorKind) -> Self {
        Self {
            kind,
            location: ExprLocation::Both,
        }
    }

    pub(crate) fn into_error(self, lhs_expr: &Expr, rhs_expr: &Expr) -> InterpreterError {
        let span = match self.location {
            ExprLocation::Lhs => lhs_expr.span(),
            ExprLocation::Rhs => rhs_expr.span(),
            ExprLocation::Both => lhs_expr.span().join(rhs_expr.span()),
        };
        InterpreterError::new(self.kind, span)
    }
}
