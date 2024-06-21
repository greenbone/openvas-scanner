// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

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
pub enum StatementKind {
    /// Either a Number, String, Boolean or Null
    Primitive,
    /// Attack category set by script_category
    AttackCategory,
    /// Is a variable
    Variable,
    /// Is a array variable, it contains the lookup token as well as an optional lookup statement
    Array(Option<Box<Statement>>),
    /// Is a call of a function
    Call(Box<Statement>),
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
    Declare(Vec<Statement>),
    /// Parameter within a function
    Parameter(Vec<Statement>),
    /// Named parameter on a function
    NamedParameter(Box<Statement>),
    /// Assignment to a variable
    Assign(TokenCategory, AssignOrder, Box<Statement>, Box<Statement>),
    /// An Operator (e.g. +, -, *)
    Operator(TokenCategory, Vec<Statement>),
    /// If statement, containing a condition, expression to be executed when the condition is true and an optional else expression
    If(
        Box<Statement>,
        Box<Statement>,
        Option<Token>,
        Option<Box<Statement>>,
    ),
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
    // The third token can be deleted as it is end statement end token
    FunctionDeclaration(Token, Box<Statement>, Box<Statement>),
    /// An empty operation, e.g. ;
    NoOp,
    /// End of File
    EoF,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Is the definition of a Statement
///
/// start returns a token of the beginning of that statement while end contains
/// the end of the statement. So as an example of the statement:
/// 'my_function(1);' start will point to 'my_function' and end to ';'.
pub struct Statement {
    kind: StatementKind,
    start: Token,
    end: Option<Token>,
}
impl Statement {
    /// Returns the StatementKind.
    ///
    /// A StatementKind is used for execution and contains all necessary data
    /// for an interpreter to execute.
    pub fn kind(&self) -> &StatementKind {
        &self.kind
    }

    /// Retrieves the stored token in a Statement.
    ///
    /// If a Statement contains multiple Statements (e.g. Declare) than just the first one is returned.
    /// Returns None on EoF, when a slice of vectors is empty or on AttackCategory
    pub fn as_token(&self) -> &Token {
        &self.start
    }

    /// Retrieves the stored token in a Statement.
    ///
    /// If a Statement contains multiple Statements (e.g. Declare) than just the first one is returned.
    /// Returns None on EoF, when a slice of vectors is empty or on AttackCategory
    pub fn as_tokens(&self) -> Vec<&Token> {
        let mut results = vec![&self.start];
        match self.kind() {
            StatementKind::Primitive
            | StatementKind::AttackCategory
            | StatementKind::Variable
            | StatementKind::NoOp
            | StatementKind::Break
            | StatementKind::Continue
            | StatementKind::Array(None)
            | StatementKind::EoF => {
                // doesn't contain further statements
            }
            StatementKind::NamedParameter(x)
            | StatementKind::Exit(x)
            | StatementKind::Return(x)
            | StatementKind::Include(x)
            | StatementKind::Call(x)
            | StatementKind::Array(Some(x)) => {
                results.extend(x.as_tokens());
            }
            StatementKind::Block(x)
            | StatementKind::Operator(_, x)
            | StatementKind::Parameter(x)
            | StatementKind::Declare(x) => {
                for stmt in x {
                    results.extend(stmt.as_tokens());
                }
            }
            StatementKind::While(x, y)
            | StatementKind::Repeat(x, y)
            | StatementKind::Assign(_, _, x, y) => {
                results.extend(x.as_tokens());
                results.extend(y.as_tokens());
            }
            StatementKind::If(r, x, y, z) => {
                results.extend(r.as_tokens());
                results.extend(x.as_tokens());
                if let Some(y) = y {
                    results.push(y);
                }
                if let Some(z) = z {
                    results.extend(z.as_tokens());
                }
            }
            StatementKind::For(r, x, y, z) => {
                results.extend(r.as_tokens());
                results.extend(x.as_tokens());
                results.extend(y.as_tokens());
                results.extend(z.as_tokens());
            }
            StatementKind::ForEach(x, y, z) => {
                results.push(x);
                results.extend(y.as_tokens());
                results.extend(z.as_tokens());
            }
            StatementKind::FunctionDeclaration(x, y, w) => {
                results.push(x);
                results.extend(y.as_tokens());
                results.extend(w.as_tokens());
            }
        };
        if let Some(t) = self.end.as_ref() {
            results.push(t);
        }
        results
    }

    /// Returns the end token
    pub fn end(&self) -> &Token {
        self.end.as_ref().unwrap_or(&self.start)
    }

    /// Returns children of blocks and calls.
    pub fn children(&self) -> &[Statement] {
        match self.kind() {
            StatementKind::If(..)
            | StatementKind::For(..)
            | StatementKind::ForEach(..)
            | StatementKind::While(..)
            | StatementKind::Repeat(..)
            | StatementKind::Assign(..)
            | StatementKind::NamedParameter(_)
            | StatementKind::Exit(_)
            | StatementKind::Return(_)
            | StatementKind::Include(_)
            | StatementKind::Array(_)
            | StatementKind::Primitive
            | StatementKind::AttackCategory
            | StatementKind::Variable
            | StatementKind::NoOp
            | StatementKind::Break
            | StatementKind::Continue
            | StatementKind::EoF => &[],

            // contains Parameter
            StatementKind::Call(x) | StatementKind::FunctionDeclaration(_, x, _) => x.children(),

            StatementKind::Block(x)
            | StatementKind::Operator(_, x)
            | StatementKind::Parameter(x)
            | StatementKind::Declare(x) => x,
        }
    }

    /// Calculates the position of the statement
    pub fn position(&self) -> (usize, usize) {
        (
            self.start.position.0,
            self.end
                .as_ref()
                .map(|x| x.position.1)
                .unwrap_or_else(|| self.start.position.1),
        )
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
    ///     .map(|s| s.find(&|s| matches!(s.kind(), nasl_syntax::StatementKind::Call(..))).len())
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
            match self.kind() {
                StatementKind::Primitive
                | StatementKind::AttackCategory
                | StatementKind::Variable
                | StatementKind::NoOp
                | StatementKind::Break
                | StatementKind::Continue
                | StatementKind::Array(None)
                | StatementKind::EoF => {
                    // doesn't contain further statements
                }
                StatementKind::NamedParameter(x)
                | StatementKind::Exit(x)
                | StatementKind::Return(x)
                | StatementKind::Include(x)
                | StatementKind::Call(x)
                | StatementKind::Array(Some(x)) => {
                    results.extend(Self::find(x, wanted));
                }
                StatementKind::Block(x)
                | StatementKind::Operator(_, x)
                | StatementKind::Parameter(x)
                | StatementKind::Declare(x) => {
                    for stmt in x {
                        results.extend(Self::find(stmt, wanted));
                    }
                }
                StatementKind::While(x, y)
                | StatementKind::Repeat(x, y)
                | StatementKind::Assign(_, _, x, y) => {
                    results.extend(Self::find(x, wanted));
                    results.extend(Self::find(y, wanted));
                }
                StatementKind::If(r, x, _, z) => {
                    results.extend(Self::find(r, wanted));
                    results.extend(Self::find(x, wanted));

                    if let Some(z) = z {
                        results.extend(Self::find(z, wanted));
                    }
                }
                StatementKind::For(r, x, y, z) => {
                    results.extend(Self::find(r, wanted));
                    results.extend(Self::find(x, wanted));
                    results.extend(Self::find(y, wanted));
                    results.extend(Self::find(z, wanted));
                }
                StatementKind::ForEach(_, y, z) => {
                    results.extend(Self::find(y, wanted));
                    results.extend(Self::find(z, wanted));
                }
                StatementKind::FunctionDeclaration(_, y, w) => {
                    results.extend(Self::find(y, wanted));
                    results.extend(Self::find(w, wanted));
                }
            };

            results
        }
    }

    /// Returns the initial token of a Statement
    pub fn start(&self) -> &Token {
        &self.start
    }

    /// Returns self if it is a returnable or an SyntaxError otherwise
    pub fn as_returnable_or_err(self) -> Result<Self, SyntaxError> {
        if self.kind().is_returnable() {
            Ok(self)
        } else {
            Err(unexpected_statement!(self))
        }
    }

    /// Creates a statement with the same start and end token
    pub fn with_start_token(token: Token, kind: StatementKind) -> Self {
        Self {
            kind,
            start: token,
            end: None,
        }
    }

    /// Creates a statement with the start and end token
    pub fn with_start_end_token(start: Token, end: Token, kind: StatementKind) -> Self {
        Self {
            kind,
            start,
            end: Some(end),
        }
    }

    /// Creates a Statement without a token.
    ///
    /// This should only be used when artificially creating a Statement without
    /// code relevance e.g. expanding i++ to 'return i and then add 1 to i'.
    pub fn without_token(kind: StatementKind) -> Self {
        Self {
            kind,
            start: Token::default(),
            end: None,
        }
    }

    pub(crate) fn set_end(&mut self, cat: Token) {
        self.end = Some(cat)
    }
}

impl std::fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let as_str_list = |v: &[Statement]| {
            v.iter()
                .map(|x| x.to_string())
                .reduce(|a, b| format!("{a}, {b}"))
                .unwrap_or_default()
        };
        let x = self.start();
        match self.kind() {
            StatementKind::Primitive => write!(f, "{}", x.category()),
            StatementKind::AttackCategory => write!(f, "{x:?}"),
            StatementKind::Variable => write!(f, "{}", x.category()),
            StatementKind::Array(e) => match e {
                Some(e) => {
                    write!(f, "{}[{e}]", x.category())
                }
                None => write!(f, "{}", x.category()),
            },
            StatementKind::Call(args) => {
                write!(f, "{}{};", x.category(), args)
            }
            StatementKind::Exit(x) => write!(f, "exit({x});"),
            StatementKind::Return(x) => write!(f, "return {x};"),
            StatementKind::Include(x) => write!(f, "include({x});"),
            StatementKind::Declare(y) => {
                write!(f, "{x} {}", as_str_list(y),)
            }
            StatementKind::Parameter(x) => write!(f, "({})", as_str_list(x),),
            StatementKind::NamedParameter(s) => write!(f, "{}: {s}", x.category()),
            StatementKind::Assign(c, o, l, r) => match (o, r.kind().clone()) {
                (AssignOrder::AssignReturn, StatementKind::NoOp) => write!(f, "{c}{l}"),
                (AssignOrder::ReturnAssign, StatementKind::NoOp) => write!(f, "{l}{c}"),
                _ => write!(f, "{l} {c} {r}"),
            },
            StatementKind::Operator(o, args) => match &args[..] {
                [l, r] => write!(f, "{l} {o} {r}"),
                [l] => write!(f, "{o}{l}"),
                _ => write!(f, "({o} ({}))", as_str_list(args)),
            },
            StatementKind::If(c, x, _, e) => {
                let r = write!(f, "if ({c}) {x}");
                if let Some(e) = e {
                    write!(f, " else {e}")
                } else {
                    r
                }
            }
            StatementKind::For(i, c, u, e) => write!(f, "for ({i}; {c}; {u}) {{ {e} }}"),
            StatementKind::While(c, e) => write!(f, "while ({c}) {{{e}}}"),
            StatementKind::Repeat(e, c) => write!(f, "repeat {e} until {c}"),
            StatementKind::ForEach(v, a, e) => {
                write!(f, "foreach {}({a}) {{{e}}}", v.category())
            }
            StatementKind::Block(..) => write!(f, "{{ ... }}"),
            StatementKind::FunctionDeclaration(n, p, _) => {
                write!(f, "function {}({}) {{ ... }}", n.category(), p)
            }
            StatementKind::NoOp => write!(f, "NoOp"),
            StatementKind::EoF => write!(f, "EoF"),
            StatementKind::Break => write!(f, "break"),
            StatementKind::Continue => write!(f, "continue"),
        }
    }
}

impl StatementKind {
    /// Returns true when Statement may returns something
    ///
    /// Since nasl is a dynamic, typeless language there is no guarantee.
    /// In uncertain things like a function it returns true.
    pub fn is_returnable(&self) -> bool {
        matches!(
            self,
            StatementKind::Primitive
                | StatementKind::Variable
                | StatementKind::Call(..)
                | StatementKind::Return(..)
                | StatementKind::Assign(
                    _,
                    AssignOrder::AssignReturn | AssignOrder::ReturnAssign,
                    _,
                    _
                )
                | StatementKind::Array(..)
                | StatementKind::Operator(..)
        )
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
            "a = 1 + 1;",
            "b = 2 * 2;",
            "a = ++a;",
            "arr = mkarray(a, b, c      );",
            "arr[++a];",
            "exit(1);",
            "return 1;",
            "include('test.inc');",
            "local_var a, b, c;",
            "global_var a, b, c;",
            "if (a) display(1); else display(2);",
            "for (i = 1; i < 10; i++) display(i);",
            "while(TRUE) display(i);",
            "foreach a(q) display(a);",
            "repeat display(\"q\"); until 1;",
            r#"{
           a;
           b;
        }"#,
            "function register_packages( buf ) { return 1; }",
        ];
        let mut tests = 0;

        let mut ri = expected.iter();
        for stmt in parser {
            let stmt = stmt.unwrap();
            let a: &str = ri.next().unwrap();
            let range = stmt.range();
            tests += 1;
            assert_eq!(&code[range], a);
        }

        assert_eq!(tests, expected.len());
    }
}
