use crate::{
    infix_extension::Infix,
    postifx_extension::Postfix,
    prefix_extension::{Prefix, PrefixState},
    token::{Category, Token, Tokenizer}, operation::Operation, error::TokenError, unexpected_token, unexpected_end,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignCategory {
    Assign,
    AssignReturn,
    ReturnAssign,

}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    RawNumber(u8),
    Primitive(Token),
    Variable(Token),
    Call(Token, Box<Statement>),
    Parameter(Vec<Statement>),
    Assign(AssignCategory, Token, Box<Statement>),

    Operator(Category, Vec<Statement>),

    If(Box<Statement>, Box<Statement>, Option<Box<Statement>>),
    Block(Vec<Statement>),
    NoOp(Option<Token>),
}

pub(crate) struct Lexer<'a> {
    pub(crate) tokenizer: Tokenizer<'a>,
    pub(crate) unhandled_token: Option<Token>,
}


impl<'a> Lexer<'a> {
    fn new(tokenizer: Tokenizer<'a>) -> Lexer<'a> {
        Lexer {
            tokenizer,
            unhandled_token: None,
        }
    }

    pub(crate) fn next(&mut self) -> Option<Token> {
        self.tokenizer.next()
    }

    pub(crate) fn expression_bp(
        &mut self,
        min_bp: u8,
        abort: Category,
    ) -> Result<Statement, TokenError> {
        let token = self
            .unhandled_token
            .or_else(|| self.next())
            .ok_or_else(|| unexpected_end!("parsing expression"))?;
        if token.category() == abort {
            return Ok(Statement::NoOp(Some(token)));
        }

        let (state, mut lhs) = self.prefix_statement(token, abort)?;
        if state == PrefixState::Break {
            return Ok(lhs);
        }
        loop {
            let token = {
                let r = match self.unhandled_token {
                    None => self.next(),
                    x => {
                        self.unhandled_token = None;
                        x
                    }
                };
                match r {
                    Some(x) => x,
                    None => break,
                }
            };
            if token.category() == abort {
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

