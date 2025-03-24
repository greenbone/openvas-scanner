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
    AnonymousFnArg, Array, ArrayAccess, AssignmentOperator, Ast, Atom, Binary, BinaryOperator,
    Block, CommaSeparated, Expr, FnArg, FnCall, FnDecl, Include, NamedFnArg, Paren, Return, Stmt,
    Unary, UnaryOperator, UnaryPostfixOperator, UnaryPrefixOperator, VarDecl, While,
};

type Result<T, E = ParseErrorKind> = std::result::Result<T, E>;

pub trait Parse: Sized {
    fn parse(parser: &mut Parser) -> Result<Self>;
}

pub trait Matches: Sized {
    fn matches(kind: &TokenKind) -> bool;

    fn peek(parser: &Parser) -> bool {
        Self::matches(parser.peek())
    }

    fn peek_next(parser: &Parser) -> bool {
        Self::matches(parser.peek_next())
    }
}

pub trait PeekParse: Sized {
    fn peek_parse(parser: &Parser) -> Option<Self>;
}

trait Delimiter: Default {
    fn start() -> TokenKind;
    fn end() -> TokenKind;
}

pub enum OptionalBlock<T> {
    Single(T),
    Block(Block<T>),
}

impl<T> From<OptionalBlock<T>> for Block<T> {
    fn from(value: OptionalBlock<T>) -> Self {
        match value {
            OptionalBlock::Single(item) => Block { items: vec![item] },
            OptionalBlock::Block(block) => block,
        }
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
        let mut stmts = vec![];
        let mut errs = vec![];
        while !self.is_at_end() {
            let result = self.parse::<Stmt>();
            // Check if any tokenization errors occured, those have priority
            // and make the actual result obtained from parsing void
            if !self.check_tokenizer_errors(&mut errs) {
                match result {
                    Ok(decl) => stmts.push(decl),
                    Err(err) => {
                        errs.push(err);
                        self.synchronize();
                    }
                }
            }
        }
        self.check_tokenizer_errors(&mut errs);
        if errs.is_empty() {
            Ok(Ast::new(stmts))
        } else {
            Err(errs)
        }
    }

    fn synchronize(&mut self) {
        while !self.is_at_end() {
            let token = self.advance();
            if token.kind == TokenKind::Semicolon {
                self.advance();
                return;
            }
            match self.peek() {
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

    fn matches(&mut self, expected: TokenKind) -> bool {
        self.peek() == &expected
    }

    fn next_matches(&mut self, expected: TokenKind) -> bool {
        self.peek_next() == &expected
    }

    fn consume_if_matches(&mut self, expected: TokenKind) -> bool {
        self.consume(expected).is_ok()
    }

    fn consume(&mut self, expected: TokenKind) -> Result<()> {
        if self.peek() != &expected {
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
        if let Some(t) = predicate(self.peek()) {
            self.advance();
            Ok(t)
        } else {
            Err(e)
        }
    }

    fn peek(&self) -> &TokenKind {
        self.cursor.peek().kind()
    }

    fn peek_next(&self) -> &TokenKind {
        self.cursor.peek_next().kind()
    }

    fn is_at_end(&self) -> bool {
        self.peek() == &TokenKind::Eof
    }
}

impl Parse for Stmt {
    fn parse(parser: &mut Parser) -> Result<Stmt> {
        if Ident::peek(parser) && AssignmentOperator::peek_next(parser) {
            Ok(Stmt::VarDecl(VarDecl::parse(parser)?))
        } else if parser.matches(TokenKind::Keyword(Keyword::Function)) {
            Ok(Stmt::FnDecl(FnDecl::parse(parser)?))
        } else if parser.matches(TokenKind::Keyword(Keyword::While)) {
            Ok(Stmt::While(While::parse(parser)?))
        } else if parser.matches(TokenKind::LeftBrace) {
            Ok(Stmt::Block(Block::parse(parser)?))
        } else if parser.matches(TokenKind::Keyword(Keyword::Return)) {
            Ok(Stmt::Return(Return::parse(parser)?))
        } else if parser.matches(TokenKind::Keyword(Keyword::Include)) {
            Ok(Stmt::Include(Include::parse(parser)?))
        } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Break)) {
            parser.consume(TokenKind::Semicolon)?;
            Ok(Stmt::Break)
        } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Continue)) {
            parser.consume(TokenKind::Semicolon)?;
            Ok(Stmt::Continue)
        } else if parser.consume_if_matches(TokenKind::Semicolon) {
            Ok(Stmt::NoOp)
        } else {
            let expr = Expr::parse(parser)?;
            parser.consume(TokenKind::Semicolon)?;
            Ok(Stmt::ExprStmt(expr))
        }
    }
}

impl<T: Parse> Parse for Block<T> {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::LeftBrace)?;
        let mut stmts = vec![];
        loop {
            if parser.consume_if_matches(TokenKind::RightBrace) {
                break;
            }
            stmts.push(T::parse(parser)?);
        }
        Ok(Block { items: stmts })
    }
}

impl<T: Parse> Parse for OptionalBlock<T> {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if parser.matches(TokenKind::LeftBrace) {
            Ok(OptionalBlock::Block(Block::parse(parser)?))
        } else {
            // Parse omitted {}: Only a single T is allowed
            let item = T::parse(parser)?;
            Ok(OptionalBlock::Single(item))
        }
    }
}

impl Parse for Include {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::Include))?;
        parser.consume(TokenKind::LeftParen)?;
        let path = Literal::parse(parser)?;
        parser.consume(TokenKind::RightParen)?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(Include { path })
    }
}

impl Parse for VarDecl {
    fn parse(parser: &mut Parser) -> Result<VarDecl> {
        let ident = Ident::parse(parser)?;
        let operator = AssignmentOperator::parse(parser)?;
        let expr = Expr::parse(parser)?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(VarDecl {
            ident,
            expr,
            operator,
        })
    }
}

impl Parse for FnDecl {
    fn parse(parser: &mut Parser) -> Result<FnDecl> {
        parser.consume(TokenKind::Keyword(Keyword::Function))?;
        let fn_name = Ident::parse(parser)?;
        let args = CommaSeparated::parse(parser)?;
        let block = Block::parse(parser)?;
        Ok(FnDecl {
            fn_name,
            args,
            block,
        })
    }
}

impl Parse for Return {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::Return))?;
        let expr = Expr::parse(parser)?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(Return { expr })
    }
}

impl Parse for While {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::While))?;
        parser.consume(TokenKind::LeftParen)?;
        let condition = Expr::parse(parser)?;
        parser.consume(TokenKind::RightParen)?;
        let block = OptionalBlock::parse(parser)?.into();
        Ok(While { condition, block })
    }
}

impl Parse for Expr {
    fn parse(parser: &mut Parser) -> Result<Expr> {
        pratt_parse_expr(parser, 0)
    }
}

fn pratt_parse_expr(parser: &mut Parser, min_bp: usize) -> Result<Expr> {
    let mut lhs = if Atom::peek(parser) {
        Expr::Atom(Atom::parse(parser)?)
    } else if parser.consume_if_matches(TokenKind::LeftParen) {
        let lhs = pratt_parse_expr(parser, 0)?;
        parser.consume(TokenKind::RightParen)?;
        lhs
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
        if matches!(
            *parser.peek(),
            TokenKind::RightBracket
                | TokenKind::RightParen
                | TokenKind::Semicolon
                | TokenKind::Eof
                | TokenKind::Comma
        ) {
            break;
        }

        if let Some(op) = UnaryPostfixOperator::peek_parse(parser) {
            let l_bp = op.left_binding_power();
            if l_bp < min_bp {
                break;
            }
            UnaryPostfixOperator::parse(parser).unwrap();
            lhs = Expr::Unary(Unary {
                op: UnaryOperator::Postfix(op),
                rhs: Box::new(lhs),
            });
            continue;
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

impl Parse for Atom {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if Literal::peek(parser) {
            let literal = Literal::parse(parser).unwrap();
            Ok(Atom::Literal(literal))
        } else if parser.matches(TokenKind::LeftBracket) {
            let array = Array::parse(parser)?;
            Ok(Atom::Array(array))
        } else {
            let ident = Ident::parse(parser)?;
            if parser.consume_if_matches(TokenKind::LeftBracket) {
                let index_expr = Box::new(Expr::parse(parser)?);
                parser.consume(TokenKind::RightBracket)?;
                Ok(Atom::ArrayAccess(ArrayAccess { index_expr, ident }))
            } else if parser.matches(TokenKind::LeftParen) {
                let args = CommaSeparated::<FnArg, Paren>::parse(parser)?;
                Ok(Atom::FnCall(FnCall {
                    fn_name: ident,
                    args,
                }))
            } else {
                Ok(Atom::Ident(ident))
            }
        }
    }
}

impl Matches for Atom {
    fn matches(kind: &TokenKind) -> bool {
        Ident::matches(kind) || Literal::matches(kind) || kind == &TokenKind::LeftBracket
    }
}

impl<Item: Parse, Delim: Delimiter> Parse for CommaSeparated<Item, Delim> {
    fn parse(parser: &mut Parser) -> Result<Self> {
        let mut items = vec![];
        parser.consume(Delim::start())?;
        loop {
            if parser.consume_if_matches(Delim::end()) {
                break;
            }
            // If we can't parse the remaining content as an item, report
            // a missing parentheses
            items.push(
                Item::parse(parser).map_err(|_| ParseErrorKind::TokenExpected(Delim::end()))?,
            );
            if !parser.consume_if_matches(TokenKind::Comma) {
                parser.consume(Delim::end())?;
                break;
            }
        }
        Ok(CommaSeparated::new(items))
    }
}

impl Parse for FnArg {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if Ident::peek(parser) && parser.next_matches(TokenKind::DoublePoint) {
            let ident = Ident::parse(parser)?;
            parser.consume(TokenKind::DoublePoint)?;
            let expr = Box::new(Expr::parse(parser)?);
            Ok(FnArg::Named(NamedFnArg { ident, expr }))
        } else {
            let expr = Box::new(Expr::parse(parser)?);
            Ok(FnArg::Anonymous(AnonymousFnArg { expr }))
        }
    }
}

impl Parse for Array {
    fn parse(parser: &mut Parser) -> Result<Self> {
        let items = CommaSeparated::parse(parser)?;
        Ok(Array { items })
    }
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
