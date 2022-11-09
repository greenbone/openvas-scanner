use crate::{
    error::TokenError,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    RawNumber(u8),
    Primitive(Token),
    Variable(Token),
    Call(Token, Box<Statement>),
    Parameter(Vec<Statement>),
    Assign(Category, AssignOrder, Token, Box<Statement>),

    Operator(Category, Vec<Statement>),

    If(Box<Statement>, Box<Statement>, Option<Box<Statement>>),
    Block(Vec<Statement>),
    NoOp(Option<Token>),
    EoF,
}

pub(crate) struct Lexer<'a> {
    pub(crate) tokenizer: Tokenizer<'a>,
    pub(crate) unhandled_token: Option<Token>,
    pub(crate) end_category: Option<Category>,
}

impl<'a> Lexer<'a> {
    pub fn new(tokenizer: Tokenizer<'a>) -> Lexer<'a> {
        Lexer {
            tokenizer,
            unhandled_token: None,
            end_category: None,
        }
    }

    pub(crate) fn next(&mut self) -> Option<Token> {
        self.unhandled_token
            .take()
            .or_else(|| self.tokenizer.next())
    }

    pub(crate) fn expression_bp(
        &mut self,
        min_bp: u8,
        abort: Category,
    ) -> Result<Statement, TokenError> {
        // reset unhandled_token when min_bp is 0
        if min_bp == 0 {
            self.unhandled_token = None;
        }
        let (state, mut lhs) = self
            .next()
            .map(|token| {
                if token.category() == abort {
                    return Ok((PrefixState::Break, Statement::NoOp(Some(token))));
                }
                self.prefix_statement(token, abort)
            })
            .unwrap_or(Ok((PrefixState::Break, Statement::EoF)))?;

        if state == PrefixState::Break {
            return Ok(lhs);
        }
        loop {
            let token = {
                match self.next() {
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
                    .postfix_statement(op, token, lhs, abort)
                    .expect("needs postfix should have been validated before")?;
                lhs = stmt;
                continue;
            }

            if let Some(min_bp_reached) = self.handle_infix(op, min_bp) {
                if !min_bp_reached {
                    self.unhandled_token = Some(token);
                    break;
                }
                lhs = self.infix_statement(op, token, lhs, abort)?;
            }
        }

        Ok(lhs)
    }
}

pub fn expression(tokenizer: Tokenizer<'_>) -> Result<Statement, TokenError> {
    //let tokenizer = Tokenizer::new(code);
    let mut lexer = Lexer::new(tokenizer);
    let init = lexer.expression_bp(0, Category::Semicolon)?;
    Ok(init)
}
