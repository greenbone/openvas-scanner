// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use core::fmt;
use std::fmt::Display;

use crate::ACT;

use crate::{unexpected_statement, SyntaxError, Token, TokenCategory};

/// Specifies the order of assignment
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignOrder {
    /// Assign first than return
    AssignReturn,
    /// Return than assign
    ReturnAssign,
}

/// Specifies the scope of a declaration
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclareScope {
    /// Variable is globally reachable
    Global,
    /// Variable is locally reachable
    Local,
}

impl Display for DeclareScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeclareScope::Global => write!(f, "global_var"),
            DeclareScope::Local => write!(f, "local_var"),
        }
    }
}

/// Is a executable step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    /// Either a Number, String, Boolean or Null
    Primitive(Token),
    /// Attack category set by script_category
    AttackCategory(ACT),
    /// Is a variable
    Variable(Token),
    /// Is a array variable, it contains the lookup token as well as an optional lookup statement
    Array(Token, Option<Box<Statement>>),
    /// Is a call of a function
    Call(Token, Vec<Statement>),
    /// Special exit call
    Exit(Box<Statement>),
    /// Special Return statement
    Return(Box<Statement>),
    /// Special Break statement
    Break,
    /// Special Continue statement
    Continue,
    /// Special include call
    Include(Box<Statement>),
    /// Declares a new variable in either global or local scope
    Declare(DeclareScope, Vec<Statement>),
    /// Parameter within a function
    Parameter(Vec<Statement>),
    /// Named parameter on a function
    NamedParameter(Token, Box<Statement>),
    /// Assignment to a variable
    Assign(TokenCategory, AssignOrder, Box<Statement>, Box<Statement>),
    /// An Operator (e.g. +, -, *)
    Operator(TokenCategory, Vec<Statement>),
    /// If statement, containing a condition, expression to be executed when the condition is true and an optional else expression
    If(Box<Statement>, Box<Statement>, Option<Box<Statement>>),
    /// For statement, containing a declaration/assignment, a condition, a execution per round before body execution, body execution
    /// e.g. `for (i = 0; i < 10; i++) display("hi");`
    For(
        Box<Statement>,
        Box<Statement>,
        Box<Statement>,
        Box<Statement>,
    ),
    /// While statement, containing a condition and a block
    While(Box<Statement>, Box<Statement>),
    /// repeat statement, containing a block and a condition
    Repeat(Box<Statement>, Box<Statement>),
    /// foreach statement, containing a variable in array and a block
    ForEach(Token, Box<Statement>, Box<Statement>),
    /// A set of expression within { ... }
    Block(Vec<Statement>),
    /// Function declaration; contains an identifier token, parameter statement and a block statement
    FunctionDeclaration(Token, Vec<Statement>, Box<Statement>),
    /// An empty operation, e.g. ;
    NoOp(Option<Token>),
    /// End of File
    EoF,
}

impl Statement {
    /// Returns true when Statement may returns something
    ///
    /// Since nasl is a dynamic, typeless language there is no guarantee.
    /// In uncertain things like a function it returns true.
    pub fn is_returnable(&self) -> bool {
        matches!(
            self,
            Statement::Primitive(_)
                | Statement::Variable(_)
                | Statement::Call(_, _)
                | Statement::Return(_)
                | Statement::Assign(
                    _,
                    AssignOrder::AssignReturn | AssignOrder::ReturnAssign,
                    _,
                    _
                )
                | Statement::Array(_, _)
                | Statement::Operator(_, _)
        )
    }

    /// Returns Self when it is returnable otherwise a unexpected statement error
    pub fn as_returnable_or_err(self) -> Result<Self, SyntaxError> {
        if self.is_returnable() {
            Ok(self)
        } else {
            Err(unexpected_statement!(self))
        }
    }

    fn first_stmts_token(stmts: &[Statement]) -> Option<&Token> {
        match stmts.first() {
            Some(stmt) => stmt.as_token(),
            None => None,
        }
    }

    /// Retrieves the stored token in a Statement.
    ///
    /// If a Statement contains multiple Statements (e.g. Declare) than just the first one is returned.
    /// Returns None on EoF, when a slice of vectors is empty or on AttackCategory
    pub fn as_token(&self) -> Option<&Token> {
        match self {
            Statement::Primitive(token) => Some(token),
            Statement::Variable(token) => Some(token),
            Statement::Array(token, _) => Some(token),
            Statement::Call(token, _) => Some(token),
            Statement::Exit(stmt) => stmt.as_token(),
            Statement::Return(stmt) => stmt.as_token(),
            Statement::Include(stmt) => stmt.as_token(),
            Statement::Declare(_, stmts) => Statement::first_stmts_token(stmts),
            Statement::Parameter(stmts) => Statement::first_stmts_token(stmts),
            Statement::NamedParameter(token, _) => Some(token),
            Statement::Assign(_, _, stmt, _) => stmt.as_token(),
            Statement::Operator(_, stmts) => Statement::first_stmts_token(stmts),
            Statement::If(stmt, _, _) => stmt.as_token(),
            Statement::For(stmt, _, _, _) => stmt.as_token(),
            Statement::While(stmt, _) => stmt.as_token(),
            Statement::Repeat(_, stmt) => stmt.as_token(),
            Statement::ForEach(token, _, _) => Some(token),
            Statement::Block(stmts) => Statement::first_stmts_token(stmts),
            Statement::FunctionDeclaration(token, _, _) => Some(token),
            Statement::NoOp(token) => token.as_ref(),
            Statement::EoF => None,
            Statement::AttackCategory(_) => None,
            Statement::Continue => None,
            Statement::Break => None,
        }
    }
}

impl fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let as_str_list = |v: &[Statement]| {
            v.iter()
                .map(|x| x.to_string())
                .reduce(|a, b| format!("{a}, {b}"))
                .unwrap_or_default()
        };
        match self {
            Statement::Primitive(x) => write!(f, "{}", x.category()),
            Statement::AttackCategory(x) => write!(f, "{x:?}"),
            Statement::Variable(x) => write!(f, "{}", x.category()),
            Statement::Array(x, e) => match e {
                Some(e) => {
                    write!(f, "{}[{e}]", x.category())
                }
                None => write!(f, "{}", x.category()),
            },
            Statement::Call(name, args) => {
                write!(f, "{}({})", name.category(), as_str_list(args))
            }
            Statement::Exit(x) => write!(f, "exit({x})"),
            Statement::Return(x) => write!(f, "return {x}"),
            Statement::Include(x) => write!(f, "include({x})"),
            Statement::Declare(s, x) => {
                write!(f, "{s} {}", as_str_list(x),)
            }
            Statement::Parameter(x) => write!(f, "({})", as_str_list(x),),
            Statement::NamedParameter(n, s) => write!(f, "{}: {s}", n.category()),
            Statement::Assign(c, o, l, r) => match (o, &**r) {
                (AssignOrder::AssignReturn, Statement::NoOp(_)) => write!(f, "{c}{l}"),
                (AssignOrder::ReturnAssign, Statement::NoOp(_)) => write!(f, "{l}{c}"),
                _ => write!(f, "{l} {c} {r}"),
            },
            Statement::Operator(o, args) => match &args[..] {
                [l, r] => write!(f, "{l} {o} {r}"),
                [l] => write!(f, "{o}{l}"),
                _ => write!(f, "({o} ({}))", as_str_list(args)),
            },
            Statement::If(c, x, e) => {
                let r = write!(f, "if ({c}) {{{x}}}");
                if let Some(e) = e {
                    write!(f, " else {{{e}}}")
                } else {
                    r
                }
            }
            Statement::For(i, c, u, e) => write!(f, "for ({i}; {c}; {u}) {{ {e} }}"),
            Statement::While(c, e) => write!(f, "while ({c}) {{{e}}}"),
            Statement::Repeat(e, c) => write!(f, "repeat {e} until {c}"),
            Statement::ForEach(v, a, e) => write!(f, "foreach {}({a}) {{{e}}}", v.category()),
            Statement::Block(_) => write!(f, "{{ ... }}"),
            Statement::FunctionDeclaration(n, p, _) => {
                write!(f, "function {}({}) {{ ... }}", n.category(), as_str_list(p))
            }
            Statement::NoOp(_) => write!(f, "NoOp"),
            Statement::EoF => write!(f, "EoF"),
            Statement::Break => write!(f, "break"),
            Statement::Continue => write!(f, "continue"),
        }
    }
}
