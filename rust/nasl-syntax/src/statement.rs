// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use core::fmt;
use std::ops::Range;

use crate::{unexpected_statement, SyntaxError, Token, TokenCategory};

/// Specifies the order of assignment
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignOrder {
    /// Assign first than return
    AssignReturn,
    /// Return than assign
    ReturnAssign,
}

/// Is a executable step.
#[derive(Clone, Debug, PartialEq, Eq)]
// TODO: change from enum to struct that contains a Kind. This would allow us to redefine Statement
// to contain start an end token, may comments so that a future formatter can just depend on
// Statement rather than have to reimplement logic
pub enum Statement {
    /// Either a Number, String, Boolean or Null
    Primitive(Token),
    /// Attack category set by script_category
    AttackCategory(Token),
    /// Is a variable
    Variable(Token),
    /// Is a array variable, it contains the lookup token as well as an optional lookup statement
    Array(Token, Option<Box<Statement>>, Option<Token>),
    /// Is a call of a function
    // TODO: change to Box<Statement> and use Parameter
    Call(Token, Vec<Statement>, Token),
    /// Special exit call
    Exit(Token, Box<Statement>, Token),
    /// Special Return statement
    Return(Token, Box<Statement>),
    /// Special Break statement
    Break(Token),
    /// Special Continue statement
    Continue(Token),
    /// Special include call
    Include(Token, Box<Statement>, Token),
    /// Declares a new variable in either global or local scope
    Declare(Token, Vec<Statement>),
    /// Parameter within a function
    Parameter(Vec<Statement>),
    /// Named parameter on a function
    NamedParameter(Token, Box<Statement>),
    /// Assignment to a variable
    Assign(TokenCategory, AssignOrder, Box<Statement>, Box<Statement>),
    /// An Operator (e.g. +, -, *)
    Operator(TokenCategory, Vec<Statement>),
    /// If statement, containing a condition, expression to be executed when the condition is true and an optional else expression
    If(
        Token,
        Box<Statement>,
        Box<Statement>,
        Option<Token>,
        Option<Box<Statement>>,
    ),
    /// For statement, containing a declaration/assignment, a condition, a execution per round before body execution, body execution
    /// e.g. `for (i = 0; i < 10; i++) display("hi");`
    For(
        Token,
        Box<Statement>,
        Box<Statement>,
        Box<Statement>,
        Box<Statement>,
    ),
    /// While statement, containing a condition and a block
    While(Token, Box<Statement>, Box<Statement>),
    /// repeat statement, containing a block and a condition
    Repeat(Token, Box<Statement>, Box<Statement>),
    /// foreach statement, containing a variable in array and a block
    ForEach(Token, Token, Box<Statement>, Box<Statement>),
    /// A set of expression within { ... }
    Block(Token, Vec<Statement>, Token),
    /// Function declaration; contains an identifier token, parameter statement and a block statement
    // TODO: change to Box<Statement> as Parameter statement for statements instead of
    // Vec<Statement>
    FunctionDeclaration(Token, Token, Vec<Statement>, Token, Box<Statement>),
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
                | Statement::Call(_, _, _)
                | Statement::Return(_, _)
                | Statement::Assign(
                    _,
                    AssignOrder::AssignReturn | AssignOrder::ReturnAssign,
                    _,
                    _
                )
                | Statement::Array(_, _, _)
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
            Statement::Continue(token)
            | Statement::Break(token)
            | Statement::AttackCategory(token)
            | Statement::Primitive(token) => Some(token),
            Statement::Variable(token) => Some(token),
            Statement::Array(token, _, _) => Some(token),
            Statement::Call(token, _, _) => Some(token),
            Statement::Exit(_, stmt, _) => stmt.as_token(),
            Statement::Return(_, stmt) => stmt.as_token(),
            Statement::Include(_, stmt, _) => stmt.as_token(),
            Statement::Declare(_, stmts) => Statement::first_stmts_token(stmts),
            Statement::Parameter(stmts) => Statement::first_stmts_token(stmts),
            Statement::NamedParameter(token, _) => Some(token),
            Statement::Assign(_, _, stmt, _) => stmt.as_token(),
            Statement::Operator(_, stmts) => Statement::first_stmts_token(stmts),
            Statement::FunctionDeclaration(kw, _, _, _, _)
            | Statement::Block(kw, _, _)
            | Statement::If(kw, _, _, _, _)
            | Statement::While(kw, _, _)
            | Statement::Repeat(kw, _, _)
            | Statement::ForEach(kw, _, _, _)
            | Statement::For(kw, _, _, _, _) => Some(kw),
            Statement::NoOp(token) => token.as_ref(),
            Statement::EoF => None,
        }
    }

    /// Retrieves the stored token in a Statement.
    ///
    /// If a Statement contains multiple Statements (e.g. Declare) than just the first one is returned.
    /// Returns None on EoF, when a slice of vectors is empty or on AttackCategory
    pub fn as_tokens(&self) -> Vec<&Token> {
        match self {
            Statement::AttackCategory(token)
            | Statement::Continue(token)
            | Statement::Break(token)
            | Statement::NoOp(Some(token))
            | Statement::Array(token, None, _)
            | Statement::Primitive(token)
            | Statement::Variable(token) => vec![token],
            Statement::Array(token, Some(stmt), end) => {
                let mut results = vec![token];
                results.extend(stmt.as_tokens());
                if let Some(end) = end {
                    results.push(end)
                }
                results
            }
            Statement::Block(kw, stmts, end) | Statement::Call(kw, stmts, end) => {
                let mut results = Vec::with_capacity(stmts.len() + 2);
                results.push(kw);
                for stmt in stmts {
                    results.extend(stmt.as_tokens());
                }
                results.push(end);
                results
            }
            Statement::Include(kw, stmt, end) | Statement::Exit(kw, stmt, end) => {
                let mut results = Vec::with_capacity(3);
                results.push(kw);
                results.extend(stmt.as_tokens());
                results.push(end);
                results
            }
            Statement::NamedParameter(kw, stmt) | Statement::Return(kw, stmt) => {
                let mut results = Vec::with_capacity(2);
                results.push(kw);
                results.extend(stmt.as_tokens());
                results
            }
            Statement::Declare(kw, stmts) => {
                let mut results = Vec::with_capacity(2);
                results.push(kw);
                for stmt in stmts {
                    results.extend(stmt.as_tokens());
                }
                results
            }
            Statement::Parameter(stmts) => stmts.iter().flat_map(|stmt| stmt.as_tokens()).collect(),
            Statement::Assign(_, _, stmt1, stmt2) => {
                let mut tokens = stmt1.as_tokens();
                tokens.extend(stmt2.as_tokens());
                tokens
            }
            Statement::Operator(_, stmts) => {
                let mut results = Vec::with_capacity(stmts.len());
                for stmt in stmts {
                    results.extend(stmt.as_tokens());
                }
                results
            }
            Statement::If(kw, cond, stmt, ekw, estmt) => {
                let mut results = vec![kw];
                results.extend(cond.as_tokens());
                results.extend(stmt.as_tokens());
                if let Some(ekw) = ekw {
                    results.push(ekw);
                }
                if let Some(estmt) = estmt {
                    results.extend(estmt.as_tokens());
                }
                results
            }
            Statement::For(kw, decl, cond, post, stmt) => {
                let mut results = vec![kw];
                results.extend(decl.as_tokens());
                results.extend(cond.as_tokens());
                results.extend(post.as_tokens());
                results.extend(stmt.as_tokens());
                results
            }
            Statement::Repeat(kw, cond, stmt) | Statement::While(kw, cond, stmt) => {
                let mut results = vec![kw];
                results.extend(cond.as_tokens());
                results.extend(stmt.as_tokens());
                results
            }
            Statement::ForEach(kw, token, arr, stmt) => {
                let mut results = vec![kw, token];
                results.extend(arr.as_tokens());
                results.extend(stmt.as_tokens());
                results
            }
            Statement::FunctionDeclaration(kw, name, params, rp, stmt) => {
                let mut results = vec![kw, name];
                for stmt in params {
                    results.extend(stmt.as_tokens());
                }
                results.push(rp);
                results.extend(stmt.as_tokens());
                results
            }
            Statement::EoF | Statement::NoOp(None) => vec![],
        }
    }

    /// Calculates the position of the statement
    pub fn position(&self) -> (usize, usize) {
        match self {
            Statement::Array(id, _, Some(end)) | Statement::Call(id, _, end) => {
                (id.position.0, end.position.1)
            }
            _ => {
                let tokens = self.as_tokens();
                if let (Some(t1), Some(t2)) = (tokens.first(), tokens.last()) {
                    (t1.position.0, t2.position.1)
                } else {
                    (0, 0)
                }
            }
        }
    }

    /// Calculates the byte range of the statement
    pub fn range(&self) -> Range<usize> {
        let (start, end) = self.position();
        Range { start, end }
    }

    /// Finds all statements in itself or itself that matches the wanted function
    ///
    /// Example:
    /// ```
    /// let code = r#"
    /// function test(a, b) {
    ///     return funker(a + b);
    /// }
    /// a = funker(1);
    /// while (funker(1) == 1) {
    ///    if (funker(2) == 2) {
    ///        return funker(2);
    ///    } else {
    ///       for ( i = funker(3); i < funker(5) + funker(5); i + funker(1))
    ///         exit(funker(10));
    ///    }
    /// }
    /// "#;
    /// let results: usize = nasl_syntax::parse(code)
    ///     .filter_map(|s| s.ok())
    ///     .map(|s| s.find(&|s| matches!(s, nasl_syntax::Statement::Call(..))).len())
    ///     .sum();
    ///
    /// assert_eq!(results, 10);
    ///
    /// ```
    ///
    pub fn find<'a, 'b, F>(&'a self, wanted: &'b F) -> Vec<&'a Statement>
    where
        F: Fn(&'a Statement) -> bool,
    {
        if wanted(self) {
            vec![self]
        } else {
            let mut results = vec![];
            match self {
                Statement::Primitive(_)
                | Statement::AttackCategory(_)
                | Statement::Variable(_)
                | Statement::NoOp(_)
                | Statement::EoF
                | Statement::Break(_)
                | Statement::Array(_, None, _)
                | Statement::Continue(_) => {
                    // doesn't contain further statements
                }
                Statement::Parameter(stmts)
                | Statement::Call(_, stmts, _)
                | Statement::Declare(_, stmts)
                | Statement::Operator(_, stmts)
                | Statement::Block(_, stmts, _) => {
                    for s in stmts {
                        results.extend(Self::find(s, wanted))
                    }
                }
                Statement::NamedParameter(_, stmt)
                | Statement::Exit(_, stmt, _)
                | Statement::Return(_, stmt)
                | Statement::Include(_, stmt, _)
                | Statement::Array(_, Some(stmt), _) => {
                    results.extend(Self::find(stmt, wanted));
                }
                Statement::While(_, stmt, stmt2)
                | Statement::Repeat(_, stmt, stmt2)
                | Statement::ForEach(_, _, stmt, stmt2)
                | Statement::Assign(_, _, stmt, stmt2) => {
                    results.extend(Self::find(stmt, wanted));
                    results.extend(Self::find(stmt2, wanted));
                }
                Statement::If(_, stmt, stmt2, _, stmt3) => {
                    results.extend(Self::find(stmt, wanted));
                    results.extend(Self::find(stmt2, wanted));
                    if let Some(stmt3) = stmt3 {
                        results.extend(Self::find(stmt3, wanted));
                    }
                }
                Statement::For(_, stmt, stmt2, stmt3, stmt4) => {
                    results.extend(Self::find(stmt, wanted));
                    results.extend(Self::find(stmt2, wanted));
                    results.extend(Self::find(stmt3, wanted));
                    results.extend(Self::find(stmt4, wanted));
                }
                Statement::FunctionDeclaration(_, _, stmts, _, stmt) => {
                    results.extend(Self::find(stmt, wanted));
                    for stmt in stmts {
                        results.extend(Self::find(stmt, wanted));
                    }
                }
            };
            results
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
            Statement::Array(x, e, _) => match e {
                Some(e) => {
                    write!(f, "{}[{e}]", x.category())
                }
                None => write!(f, "{}", x.category()),
            },
            Statement::Call(name, args, _) => {
                write!(f, "{}({});", name.category(), as_str_list(args))
            }
            Statement::Exit(_, x, _) => write!(f, "exit({x});"),
            Statement::Return(_, x) => write!(f, "return {x};"),
            Statement::Include(_, x, _) => write!(f, "include({x});"),
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
            Statement::If(_, c, x, _, e) => {
                let r = write!(f, "if ({c}) {x}");
                if let Some(e) = e {
                    write!(f, " else {e}")
                } else {
                    r
                }
            }
            Statement::For(_, i, c, u, e) => write!(f, "for ({i}; {c}; {u}) {{ {e} }}"),
            Statement::While(_, c, e) => write!(f, "while ({c}) {{{e}}}"),
            Statement::Repeat(_, e, c) => write!(f, "repeat {e} until {c}"),
            Statement::ForEach(_, v, a, e) => write!(f, "foreach {}({a}) {{{e}}}", v.category()),
            Statement::Block(..) => write!(f, "{{ ... }}"),
            Statement::FunctionDeclaration(_, n, p, _, _) => {
                write!(f, "function {}({}) {{ ... }}", n.category(), as_str_list(p))
            }
            Statement::NoOp(_) => write!(f, "NoOp"),
            Statement::EoF => write!(f, "EoF"),
            Statement::Break(_) => write!(f, "break"),
            Statement::Continue(_) => write!(f, "continue"),
        }
    }
}

#[cfg(test)]
mod position {
    use crate::parse;

    #[test]
    fn assignment() {
        let code = r#"
        a = 1 + 1;
        b = 2 * 2;
        a = ++a;
        arr = mkarray(a, b, c      );
        arr[++a];
        exit(1);
        return 1;
        include('test.inc');
        local_var a, b, c;
        global_var a, b, c;
        if (a) display(1); else display(2);
        for (i = 1; i < 10; i++) display(i);
        while(TRUE) display(i);
        foreach a(q) display(a);
        repeat display("q"); until 1;
        {
           a;
           b;
        }
        function register_packages( buf ) { return 1; }
        "#;
        let parser = parse(code);
        let expected = [
            "a = 1 + 1",
            "b = 2 * 2",
            "a = ++a",
            "arr = mkarray(a, b, c      )",
            "arr[++a]",
            "exit(1)",
            "return 1",
            "include('test.inc')",
            "local_var a, b, c",
            "global_var a, b, c",
            "if (a) display(1); else display(2)",
            "for (i = 1; i < 10; i++) display(i)",
            "while(TRUE) display(i)",
            "foreach a(q) display(a)",
            "repeat display(\"q\"); until 1",
            r#"{
           a;
           b;
        }"#,
            "function register_packages( buf ) { return 1; }",
        ];
        let ranges: Vec<_> = parser.map(|x| x.unwrap().range()).collect();

        let mut ri = expected.iter();
        assert_eq!(ranges.len(), expected.len());
        for range in ranges {
            let a: &str = ri.next().unwrap();
            assert_eq!(&code[range], a);
        }
    }
}
