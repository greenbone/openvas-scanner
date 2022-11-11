//! Lexer is used to parse a single statement based on token::Tokenizer.
use crate::{
    error::SyntaxError,
    infix_extension::Infix,
    operation::Operation,
    postifx_extension::Postfix,
    prefix_extension::{Prefix, PrefixState},
    token::{Category, Token, Tokenizer},
    unexpected_token,
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
    /// Either a Number or a String
    Primitive(Token),
    /// Is a variable
    Variable(Token),
    /// Is a call of a function
    Call(Token, Box<Statement>),
    /// Declares a new variable in either global or local scope
    Declare(DeclareScope, Vec<Statement>),
    /// Parameter within a function
    Parameter(Vec<Statement>),
    /// Assignment to a variable
    Assign(Category, AssignOrder, Token, Box<Statement>),
    /// An Operator (e.g. +, -, *)
    Operator(Category, Vec<Statement>),
    /// If statement, containing a condition, expression to be executed when the condition is true and an optional else expression
    If(Box<Statement>, Box<Statement>, Option<Box<Statement>>),
    /// A set of expression within { ... }
    Block(Vec<Statement>),
    /// An empty operation, e.g. ;
    NoOp(Option<Token>),
    /// End of File
    EoF,
}

/// Is used to parse Token to Statement
pub struct Lexer<'a> {
    pub(crate) tokenizer: Tokenizer<'a>,
    pub(crate) unhandled_token: Option<Token>,
    pub(crate) end_category: Option<Category>,
}

impl<'a> Lexer<'a> {
    /// Creates a Lexer
    pub fn new(tokenizer: Tokenizer<'a>) -> Lexer<'a> {
        Lexer {
            tokenizer,
            unhandled_token: None,
            end_category: None,
        }
    }

    /// Returns next token of tokenizer
    pub(crate) fn token(&mut self) -> Option<Token> {
        self.unhandled_token
            .take()
            .or_else(|| self.tokenizer.next())
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
        abort: Category,
    ) -> Result<Statement, SyntaxError> {
        // reset unhandled_token when min_bp is 0
        if min_binding_power == 0 {
            self.unhandled_token = None;
            self.end_category = None;
        }
        let (state, mut left) = self
            .token()
            .map(|token| {
                if token.category() == abort {
                    return Ok((PrefixState::Break, Statement::NoOp(Some(token))));
                }
                self.prefix_statement(token, abort)
            })
            .unwrap_or(Ok((PrefixState::Break, Statement::EoF)))?;

        if state == PrefixState::Break {
            return Ok(left);
        }
        loop {
            let token = {
                match self.token() {
                    Some(x) => x,
                    None => break,
                }
            };
            if token.category() == abort {
                // to be able to verify abort condition.
                self.end_category = Some(abort);
                // set unhandled_token to skip one next call
                self.unhandled_token = Some(token);
                break;
            }
            let op = Operation::new(token).ok_or_else(|| unexpected_token!(token))?;

            if self.needs_postfix(op) {
                let stmt = self
                    .postfix_statement(op, token, left, abort)
                    .expect("needs postfix should have been validated before")?;
                left = stmt;
                continue;
            }

            if let Some(min_bp_reached) = self.needs_infix(op, min_binding_power) {
                if !min_bp_reached {
                    self.unhandled_token = Some(token);
                    break;
                }
                left = self.infix_statement(op, token, left, abort)?;
            }
        }

        Ok(left)
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Statement, SyntaxError>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.statement(0, Category::Semicolon);
        if result == Ok(Statement::EoF) {
            None
        } else {
            Some(result)
        }
    }
}
