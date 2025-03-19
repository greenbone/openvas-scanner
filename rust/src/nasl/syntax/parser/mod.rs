mod cursor;
pub mod error;
pub mod grammar;
#[cfg(test)]
mod tests;

use std::fmt::Debug;

use cursor::Cursor;
use error::{ParseError, ParseErrorKind};

use crate::nasl::error::Span;

use super::{Keyword, Token, TokenKind, Tokenizer};
use grammar::{
    AssignmentOperator, Ast, Binary, Declaration, Expr, Grouping, Ident, Stmt, Unary,
    UnaryOperator, VariableDecl,
};

type Result<T, E = ParseErrorKind> = std::result::Result<T, E>;

pub trait Parse: Sized {
    type Output: Debug;
    fn parse(parser: &mut Parser) -> Result<Self::Output>;
}

pub trait Matches: Sized {
    fn matches(kind: &TokenKind) -> bool;

    fn peek(parser: &Parser) -> bool {
        Self::matches(parser.peek().kind())
    }

    fn peek_next(parser: &Parser) -> bool {
        Self::matches(parser.peek_next().kind())
    }
}

pub struct Parser {
    cursor: Cursor,
}

impl Parser {
    pub fn new(tokenizer: Tokenizer) -> Self {
        Self {
            cursor: Cursor::new(tokenizer).unwrap(),
        }
    }

    pub fn parse<T: Parse>(&mut self) -> Result<<T as Parse>::Output, ParseError> {
        let pos_before = self.cursor.current_token_start();
        let result = T::parse(self);
        let pos_after = self.cursor.current_token_end();
        let span = Span::new(pos_before, pos_after);
        result.map_err(|err| err.to_error(span))
    }

    fn check_tokenizer_errors(&mut self, errs: &mut Vec<ParseError>) -> bool {
        if self.cursor.has_errors() {
            for e in self.cursor.drain_errors() {
                errs.push(e.into());
            }
            self.synchronize();
            true
        } else {
            false
        }
    }

    pub fn parse_program(&mut self) -> Result<Ast, Vec<ParseError>> {
        let mut decls = vec![];
        let mut errs = vec![];
        while !self.is_at_end() {
            let result = self.parse::<Declaration>();
            // Check if any tokenization errors occured, those have priority
            // and make the actual result obtained from parsing void
            if !self.check_tokenizer_errors(&mut errs) {
                match result {
                    Ok(decl) => decls.push(decl),
                    Err(err) => {
                        errs.push(err);
                        self.synchronize();
                    }
                }
            }
        }
        self.check_tokenizer_errors(&mut errs);
        if errs.is_empty() {
            Ok(Ast::new(decls))
        } else {
            Err(errs)
        }
    }

    fn synchronize(&mut self) {
        while !self.is_at_end() {
            let token = self.advance();
            if token.kind == TokenKind::Semicolon {
                return;
            }
            match self.peek().kind {
                TokenKind::Keyword(Keyword::LocalVar) => {
                    return;
                }
                _ => {}
            }
        }
    }

    fn matches(&mut self, token_kind: TokenKind) -> bool {
        let matches = self.check(token_kind);
        if matches {
            self.advance();
        }
        matches
    }

    fn check(&mut self, token_kind: TokenKind) -> bool {
        &self.peek().kind == &token_kind
    }

    fn peek(&self) -> &Token {
        self.cursor.peek()
    }

    fn peek_next(&self) -> &Token {
        self.cursor.peek_next()
    }

    fn previous(&mut self) -> &Token {
        self.cursor.previous()
    }

    fn advance(&mut self) -> Token {
        self.cursor.advance()
    }

    fn consume(&mut self, expected: TokenKind) -> Result<()> {
        if self.peek().kind != expected {
            Err(ParseErrorKind::TokenExpected(expected))
        } else {
            self.advance();
            Ok(())
        }
    }

    fn consume_pat<T>(
        &mut self,
        predicate: impl Fn(&TokenKind) -> Option<T>,
        e: ParseErrorKind,
    ) -> Result<T> {
        if let Some(t) = predicate(self.peek().kind()) {
            self.advance();
            Ok(t)
        } else {
            Err(e)
        }
    }

    fn is_at_end(&self) -> bool {
        &self.peek().kind == &TokenKind::Eof
    }
}

impl Parse for Declaration {
    type Output = Declaration;

    fn parse(parser: &mut Parser) -> Result<Declaration> {
        if let TokenKind::Ident(_) = parser.peek().kind() {
            if AssignmentOperator::peek_next(parser) {
                return Ok(Declaration::VariableDecl(VariableDecl::parse(parser)?));
            }
        }
        let expr = Expr::parse(parser)?;
        let _ = parser.consume(TokenKind::Semicolon)?;
        Result::Ok(Declaration::Stmt(Stmt::ExprStmt(expr)))
    }
}

impl Parse for VariableDecl {
    type Output = VariableDecl;

    fn parse(parser: &mut Parser) -> Result<VariableDecl> {
        let ident = Ident::parse(parser)?;
        let operator = AssignmentOperator::parse(parser)?;
        let expr = Expr::parse(parser)?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(VariableDecl {
            ident,
            expr,
            operator,
        })
    }
}

impl Parse for Expr {
    type Output = Expr;

    fn parse(parser: &mut Parser) -> Result<Expr> {
        Result::Ok(Equality::parse(parser)?)
    }
}

trait BinaryOperator {
    type Subtype;

    fn token_kinds() -> impl Iterator<Item = TokenKind>;
}

impl<T> Parse for T
where
    T: BinaryOperator,
    <T as BinaryOperator>::Subtype: Parse<Output = Expr>,
{
    type Output = Expr;

    fn parse(parser: &mut Parser) -> Result<Expr> {
        let mut left = T::Subtype::parse(parser)?;
        while T::token_kinds().any(|kind| parser.peek().kind() == &kind) {
            let operator = grammar::BinaryOperator::parse(parser)?;
            let right = T::Subtype::parse(parser)?;
            left = Expr::Binary(Binary {
                left: Box::new(left),
                operator,
                right: Box::new(right),
            });
        }
        Ok(left)
    }
}

struct Equality;

impl BinaryOperator for Equality {
    type Subtype = Comparison;

    fn token_kinds() -> impl Iterator<Item = TokenKind> {
        [
            TokenKind::BangEqual,
            TokenKind::EqualEqual,
            TokenKind::BangTilde,
            TokenKind::EqualTilde,
        ]
        .into_iter()
    }
}

struct Comparison;

impl BinaryOperator for Comparison {
    type Subtype = Term;

    fn token_kinds() -> impl Iterator<Item = TokenKind> {
        [
            TokenKind::Greater,
            TokenKind::GreaterGreater,
            TokenKind::GreaterLess,
            TokenKind::GreaterEqual,
            TokenKind::Less,
            TokenKind::LessLess,
            TokenKind::LessEqual,
            TokenKind::GreaterGreaterGreater,
            TokenKind::GreaterBangLess,
        ]
        .into_iter()
    }
}

struct Term;

impl BinaryOperator for Term {
    type Subtype = Factor;

    fn token_kinds() -> impl Iterator<Item = TokenKind> {
        [
            TokenKind::Plus,
            TokenKind::Minus,
            TokenKind::Slash,
            TokenKind::Star,
        ]
        .into_iter()
    }
}

struct Factor;

impl BinaryOperator for Factor {
    type Subtype = Unary;

    fn token_kinds() -> impl Iterator<Item = TokenKind> {
        [TokenKind::Star, TokenKind::Slash, TokenKind::Percent].into_iter()
    }
}

impl Parse for Unary {
    type Output = Expr;

    fn parse(parser: &mut Parser) -> Result<Expr> {
        if UnaryOperator::peek(parser) {
            let operator = UnaryOperator::parse(parser)?;
            let right = Unary::parse(parser)?;
            Ok(Expr::Unary(Unary {
                operator,
                right: Box::new(right),
            }))
        } else {
            Primary::parse(parser)
        }
    }
}

struct Primary;

impl Parse for Primary {
    type Output = Expr;

    fn parse(parser: &mut Parser) -> Result<Expr> {
        if let TokenKind::Ident(ident) = &parser.peek().kind {
            let res = Ok(Expr::Ident(Ident {
                ident: ident.clone(),
            }));
            parser.advance();
            res
        } else if let TokenKind::Literal(lit) = &parser.peek().kind {
            let res = Ok(Expr::Literal(lit.clone()));
            parser.advance();
            res
        } else if parser.matches(TokenKind::LeftParen) {
            let expr = Box::new(Expr::parse(parser)?);
            let grouping = Expr::Grouping(Grouping { expr });
            parser.consume(TokenKind::RightParen)?;
            Ok(grouping)
        } else {
            Err(ParseErrorKind::ExpressionExpected)
        }
    }
}

impl Parse for Ident {
    type Output = Ident;

    fn parse(parser: &mut Parser) -> Result<Self::Output> {
        parser.consume_pat(
            |kind| {
                if let TokenKind::Ident(ident) = kind {
                    Some(Ident {
                        ident: ident.clone(),
                    })
                } else {
                    None
                }
            },
            ParseErrorKind::IdentExpected,
        )
    }
}
