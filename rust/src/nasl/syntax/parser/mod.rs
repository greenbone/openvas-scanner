pub mod error;
pub mod grammar;
#[cfg(test)]
mod tests;

use std::{fmt::Debug, ops::Range};

use error::{ParseError, ParseErrorKind};

use super::{Keyword, Token, TokenKind};
use grammar::{Ast, Binary, Declaration, Expr, Grouping, Ident, Stmt, Unary};

#[derive(Default, Clone, Copy)]
struct TokenIndex(usize);

type ParseResult<T> = Result<T, ParseErrorKind>;

pub trait Parse: Sized {
    type Output: Debug;
    fn parse(parser: &mut Parser) -> ParseResult<Self::Output>;
}

#[derive(Clone)]
pub struct Parser {
    tokens: Vec<Token>,
    position: TokenIndex,
}

impl Parser {
    pub fn new(mut tokens: Vec<Token>) -> Self {
        // TODO move this to the tokenizer eventually
        let position = tokens.last().map(|token| token.position.1).unwrap_or(0);
        tokens.push(Token {
            position: (position, position + 1),
            kind: TokenKind::Eof,
        });

        Self {
            tokens,
            position: TokenIndex::default(),
        }
    }

    pub fn parse<T: Parse>(&mut self) -> Result<<T as Parse>::Output, ParseError> {
        let pos_before = self.position;
        let result = T::parse(self);
        let pos_after = self.position;
        let range = self.get_token_range(pos_before, pos_after);
        result.map_err(|err| err.to_error(range))
    }

    pub fn parse_program(&mut self) -> Result<Ast, Vec<ParseError>> {
        let mut decls = vec![];
        let mut errs = vec![];
        while !self.is_at_end() {
            let result = self.parse::<Declaration>();
            match result {
                Ok(stmt) => decls.push(stmt),
                Err(err) => {
                    errs.push(err);
                    self.synchronize();
                }
            }
        }
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
        &self.tokens[self.position.0]
    }

    fn previous(&mut self) -> Token {
        self.tokens[self.position.0 - 1].clone()
    }

    fn advance(&mut self) -> Token {
        self.position.0 += 1;
        self.previous().clone()
    }

    fn consume(&mut self, expected: TokenKind, e: ParseErrorKind) -> Result<(), ParseErrorKind> {
        if self.peek().kind != expected {
            Err(e)
        } else {
            self.advance();
            Ok(())
        }
    }

    fn get_token_range(&self, pos_before: TokenIndex, pos_after: TokenIndex) -> Range<usize> {
        self.tokens[pos_before.0].start()..self.tokens[pos_after.0 - 1].end()
    }

    fn is_at_end(&self) -> bool {
        &self.peek().kind == &TokenKind::Eof
    }
}

impl Parse for Declaration {
    type Output = Declaration;

    fn parse(parser: &mut Parser) -> ParseResult<Declaration> {
        let expr = Expr::parse(parser)?;
        let _ = parser.consume(TokenKind::Semicolon, ParseErrorKind::SemicolonExpected)?;
        ParseResult::Ok(Declaration::Stmt(Stmt::ExprStmt(expr)))
    }
}

impl Parse for Expr {
    type Output = Expr;

    fn parse(parser: &mut Parser) -> ParseResult<Expr> {
        ParseResult::Ok(Equality::parse(parser)?)
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

    fn parse(parser: &mut Parser) -> ParseResult<Expr> {
        let mut left = T::Subtype::parse(parser)?;
        while T::token_kinds().any(|kind| parser.matches(kind)) {
            let operator = parser.previous();
            let right = T::Subtype::parse(parser)?;
            left = Expr::Binary(Binary {
                left: Box::new(left),
                operator: operator,
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
            TokenKind::GreaterGreaterEqual,
            TokenKind::LessLessEqual,
            TokenKind::GreaterBangLess,
            TokenKind::GreaterGreaterGreaterEqual,
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
        [TokenKind::Star, TokenKind::Slash].into_iter()
    }
}

impl Parse for Unary {
    type Output = Expr;

    fn parse(parser: &mut Parser) -> ParseResult<Expr> {
        if parser.matches(TokenKind::Bang) || parser.matches(TokenKind::Minus) {
            let operator = parser.previous();
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

    fn parse(parser: &mut Parser) -> ParseResult<Expr> {
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
            parser.consume(TokenKind::RightParen, ParseErrorKind::ClosingParenExpected)?;
            Ok(grouping)
        } else {
            Err(ParseErrorKind::ExpressionExpected)
        }
    }
}
