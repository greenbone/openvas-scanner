mod cursor;
pub mod error;
pub mod grammar;
#[cfg(test)]
mod tests;

use cursor::Cursor;
use error::{ParseError, ParseErrorKind};

use crate::nasl::error::Span;

use super::{Ident, Keyword, Token, TokenKind, Tokenizer, token::Literal};
use grammar::{
    AssignmentOperator, Ast, Binary, BinaryOperator, Declaration, Expr, Stmt, Unary, UnaryOperator,
    UnaryPrefixOperator, VariableDecl,
};

type Result<T, E = ParseErrorKind> = std::result::Result<T, E>;

pub trait Parse: Sized {
    fn parse(parser: &mut Parser) -> Result<Self>;
}

pub trait Matches: Sized {
    fn matches(kind: &TokenKind) -> bool;

    fn peek(parser: &Parser) -> bool {
        Self::matches(parser.cursor.peek().kind())
    }

    fn peek_next(parser: &Parser) -> bool {
        Self::matches(parser.cursor.peek_next().kind())
    }
}

pub trait PeekParse: Sized {
    fn peek_parse(parser: &mut Parser) -> Option<Self>;
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

    pub fn parse<T: Parse>(&mut self) -> Result<T, ParseError> {
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
            match self.cursor.peek().kind {
                TokenKind::Keyword(Keyword::LocalVar) => {
                    return;
                }
                _ => {}
            }
        }
    }

    fn advance(&mut self) -> Token {
        self.cursor.advance()
    }

    fn consume(&mut self, expected: TokenKind) -> Result<()> {
        if self.cursor.peek().kind != expected {
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
        if let Some(t) = predicate(self.cursor.peek().kind()) {
            self.advance();
            Ok(t)
        } else {
            Err(e)
        }
    }

    fn is_at_end(&self) -> bool {
        &self.cursor.peek().kind == &TokenKind::Eof
    }
}

impl Parse for Declaration {
    fn parse(parser: &mut Parser) -> Result<Declaration> {
        if Ident::peek(parser) {
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
    fn parse(parser: &mut Parser) -> Result<Expr> {
        pratt_parse_expr(parser, 0)
    }
}

fn pratt_parse_expr(parser: &mut Parser, min_bp: usize) -> Result<Expr> {
    let mut lhs = if Ident::peek(parser) {
        Expr::Ident(Ident::parse(parser)?)
    } else if Literal::peek(parser) {
        Expr::Literal(Literal::parse(parser)?)
    } else if UnaryPrefixOperator::peek(parser) {
        let op = UnaryPrefixOperator::parse(parser)?;
        let r_bp = op.right_binding_power();
        Expr::Unary(Unary {
            op: UnaryOperator::Prefix(op),
            rhs: Box::new(pratt_parse_expr(parser, r_bp)?),
        })
    } else {
        return Err(ParseErrorKind::ExpressionExpected);
    };

    loop {
        if parser.is_at_end() {
            break;
        } else if parser.cursor.peek().kind() == &TokenKind::Semicolon {
            break;
        }

        let op = BinaryOperator::peek_parse(parser)
            .ok_or_else(|| ParseErrorKind::TokenExpected(TokenKind::Semicolon))?;
        let (l_bp, r_bp) = op.binding_power();
        if l_bp < min_bp {
            break;
        }
        let _ = BinaryOperator::parse(parser).unwrap();
        let rhs = pratt_parse_expr(parser, r_bp)?;
        lhs = Expr::Binary(Binary {
            lhs: Box::new(lhs),
            op,
            rhs: Box::new(rhs),
        });
    }
    Ok(lhs)
}

macro_rules! impl_trivial_parse {
    ($ty: ty, $kind: ident, $err: expr) => {
        impl Parse for $ty {
            fn parse(parser: &mut Parser) -> Result<Self> {
                parser.consume_pat(
                    |kind| {
                        if let TokenKind::$kind(x) = kind {
                            Some(x.clone())
                        } else {
                            None
                        }
                    },
                    $err,
                )
            }
        }

        impl Matches for $ty {
            fn matches(kind: &TokenKind) -> bool {
                matches!(kind, TokenKind::$kind(_))
            }
        }
    };
}

impl_trivial_parse!(Ident, Ident, ParseErrorKind::IdentExpected);
impl_trivial_parse!(Literal, Literal, ParseErrorKind::LiteralExpected);
