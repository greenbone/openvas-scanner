//! Lexer is used to parse a single statement based on token::Tokenizer.
use std::ops::Range;

use crate::{
    error::SyntaxError,
    infix_extension::Infix,
    operation::Operation,
    postifx_extension::Postfix,
    prefix_extension::{Prefix, PrefixState},
    token::{Category, Token, Tokenizer},
    unexpected_statement, unexpected_token,
};

/// Specifies the order of assignment
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignOrder {
    /// Just assign don't return
    Assign,
    /// Assign first than return
    AssignReturn,
    /// Retutn than assign
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
    /// Represents a Number that is not directly in the source code but calculated (e.g. on i++)
    RawNumber(u8),
    /// Either a Number, String, Boolean or Null
    Primitive(Token),
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
    Assign(Category, AssignOrder, Box<Statement>, Box<Statement>),
    /// An Operator (e.g. +, -, *)
    Operator(Category, Vec<Statement>),
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
    /// FCT_ANON_ARGS is a special array used in NASL to gather anonymous arguments within functions
    FCTAnonArgs(Option<Box<Statement>>),
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
    /// Since nasl is a dynamic, typeless language there is no guarantue.
    /// In uncertain things like a function it returns true.
    pub fn is_returnable(&self) -> bool {
        matches!(
            self,
            Statement::RawNumber(_)
                | Statement::Primitive(_)
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
}

/// Is used to parse Token to Statement
pub struct Lexer<'a> {
    tokenizer: Tokenizer<'a>,
    pub(crate) unhandled_token: Option<Token>,
}

impl<'a> Lexer<'a> {
    /// Creates a Lexer
    pub fn new(tokenizer: Tokenizer<'a>) -> Lexer<'a> {
        Lexer {
            tokenizer,
            unhandled_token: None,
        }
    }

    /// Returns next token of tokenizer
    pub(crate) fn token(&mut self) -> Option<Token> {
        while let Some(token) = self
            .unhandled_token
            .take()
            .or_else(|| self.tokenizer.next())
        {
            if token.category() == Category::Comment {
                continue;
            }
            return Some(token);
        }
        None
    }

    /// Returns the next expression.
    ///
    /// It uses a prefix_extension to verify if a token is prefix relevant and if parsing should continue
    /// or stop. This is crucial for keyword handling.
    ///
    /// Afterwards it verifies via the postifx_extension if a token is postfix relevant.
    ///
    /// Last but not least it verifies if a token is infix relevant if the binding power of infix token
    /// is lower than the given min_bp it aborts. This is done to handle the correct operation order.
    pub(crate) fn statement(
        &mut self,
        min_binding_power: u8,
        abort: &impl Fn(Category) -> bool,
    ) -> Result<(bool, Statement), SyntaxError> {
        // reset unhandled_token when min_bp is 0
        let (state, mut left) = self
            .token()
            .map(|token| {
                if abort(token.category()) {
                    return Ok((PrefixState::Break, Statement::NoOp(Some(token))));
                }
                self.prefix_statement(token, abort)
            })
            .unwrap_or(Ok((PrefixState::Break, Statement::EoF)))?;
        match state {
            PrefixState::Continue => {}
            PrefixState::OpenEnd => return Ok((false, left)),
            PrefixState::Break => return Ok((true, left)),
        }

        let mut end_statement = false;
        loop {
            let token = {
                match self.token() {
                    Some(x) => x,
                    None => break,
                }
            };
            if abort(token.category()) {
                end_statement = true;
                break;
            }
            let op = Operation::new(token).ok_or_else(|| unexpected_token!(token))?;

            if self.needs_postfix(op) {
                let (end, stmt) = self
                    .postfix_statement(op, token, left, abort)
                    .expect("needs postfix should have been validated before")?;
                left = stmt;
                if end {
                    end_statement = true;
                    break;
                }
                continue;
            }

            if let Some(min_bp_reached) = self.needs_infix(op, min_binding_power) {
                if !min_bp_reached {
                    self.unhandled_token = Some(token);
                    break;
                }
                let (end, nl) = self.infix_statement(op, token, left, abort)?;
                left = nl;
                if end {
                    end_statement = true;
                    break;
                }
            }
        }

        Ok((end_statement, left))
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Statement, SyntaxError>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.statement(0, &|cat| cat == Category::Semicolon);
        match result {
            Ok((true, Statement::EoF)) => None,
            Ok((true, stmt)) => Some(Ok(stmt)),
            Ok((false, stmt)) => {
                if matches!(stmt, Statement::NoOp(_)) {
                    Some(Ok(stmt))
                } else {
                    Some(Err(unexpected_statement!(stmt)))
                }
            }
            Err(x) => Some(Err(x)),
        }
    }
}
