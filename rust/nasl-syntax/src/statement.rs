use core::fmt;

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
    Call(Token, Box<Statement>),
    /// Special exit call
    Exit(Box<Statement>),
    /// Special Return statement
    Return(Box<Statement>),
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
    #[inline(always)]
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
    #[inline(always)]
    pub fn as_returnable_or_err(self) -> Result<Self, SyntaxError> {
        if self.is_returnable() {
            Ok(self)
        } else {
            Err(unexpected_statement!(self))
        }
    }

    #[inline(always)]
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
    #[inline(always)]
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
        }
    }
}

impl fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Statement::Primitive(_) => write!(f, "Primitive"),
            Statement::AttackCategory(_) => write!(f, "AttackCategory"),
            Statement::Variable(_) => write!(f, "Variable"),
            Statement::Array(_, _) => write!(f, "Array"),
            Statement::Call(_, _) => write!(f, "Call"),
            Statement::Exit(_) => write!(f, "Exit"),
            Statement::Return(_) => write!(f, "Return"),
            Statement::Include(_) => write!(f, "Include"),
            Statement::Declare(_, _) => write!(f, "Declare"),
            Statement::Parameter(_) => write!(f, "Parameter"),
            Statement::NamedParameter(_, _) => write!(f, "NamedParameter"),
            Statement::Assign(_, _, _, _) => write!(f, "Assign"),
            Statement::Operator(_, _) => write!(f, "Operator"),
            Statement::If(_, _, _) => write!(f, "If"),
            Statement::For(_, _, _, _) => write!(f, "For"),
            Statement::While(_, _) => write!(f, "While"),
            Statement::Repeat(_, _) => write!(f, "Repeat"),
            Statement::ForEach(_, _, _) => write!(f, "ForEach"),
            Statement::Block(_) => write!(f, "Block"),
            Statement::FunctionDeclaration(_, _, _) => write!(f, "FunctionDeclaration"),
            Statement::NoOp(_) => write!(f, "NoOp"),
            Statement::EoF => write!(f, "EoF"),
        }
    }
}
