mod cursor;
mod error;
pub mod grammar;
#[cfg(test)]
mod tests;

use cursor::{Cursor, Peek};
pub use error::ErrorKind as ParseErrorKind;
pub use error::SpannedError as ParseError;
use error::SpannedError;
use error::{Error, ErrorKind};

use crate::nasl::error::Span;

use super::{Ident, Keyword, Token, TokenKind, Tokenizer, token::Literal};
use grammar::{
    AnonymousFnArg, Array, ArrayAccess, AssignmentOperator, Ast, Atom, Binary, BinaryOperator,
    Block, CommaSeparated, Expr, FnArg, FnCall, FnDecl, Include, NamedFnArg, Return, Stmt, Unary,
    UnaryOperator, UnaryPostfixOperator, UnaryPrefixOperator, VarDecl, VarScope, VarScopeDecl,
    While,
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub(self) trait Parse: Sized {
    fn parse(parser: &mut Parser) -> Result<Self>;
}

pub(self) trait Matches: Sized {
    fn matches(p: &impl Peek) -> bool;
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

    fn parse_span<T: Parse>(&mut self) -> Result<T> {
        let pos_before = self.cursor.current_token_start();
        let result = self.parse();
        let pos_after = self.cursor.current_token_end();
        let span = Span::new(pos_before, pos_after);
        result.map_err(|err| err.add_span(span))
    }

    fn check_tokenizer_errors(&mut self, errs: &mut Vec<SpannedError>) -> bool {
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

    pub fn parse_program(&mut self) -> Result<Ast, Vec<SpannedError>> {
        let mut stmts = vec![];
        let mut errs = vec![];
        while !self.is_at_end() {
            let result = self.parse_span::<Stmt>();
            // Check if any tokenization errors occured, those have priority
            // and make the actual result obtained from parsing void
            if !self.check_tokenizer_errors(&mut errs) {
                match result {
                    Ok(decl) => stmts.push(decl),
                    Err(err) => {
                        // We know the error has a span since it originates from
                        // parse_span
                        errs.push(err.unwrap_as_spanned());
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

    fn parse<T: Parse>(&mut self) -> Result<T> {
        T::parse(self)
    }

    fn matches<T: Matches>(&self) -> bool {
        T::matches(&self.cursor)
    }

    fn matches_next<T: Matches>(&self) -> bool {
        let lookahead = self.cursor.lookahead();
        T::matches(&lookahead)
    }

    fn advance(&mut self) -> Token {
        self.cursor.advance()
    }

    fn matches_token(&mut self, expected: TokenKind) -> bool {
        self.peek() == &expected
    }

    fn next_matches_token(&mut self, expected: TokenKind) -> bool {
        self.peek_next() == &expected
    }

    fn consume_if_matches(&mut self, expected: TokenKind) -> bool {
        self.consume(expected).is_ok()
    }

    fn consume(&mut self, expected: TokenKind) -> Result<()> {
        if self.peek() != &expected {
            Err(ErrorKind::TokenExpected(expected).into())
        } else {
            self.advance();
            Ok(())
        }
    }

    fn consume_pat<T>(
        &mut self,
        predicate: impl Fn(&TokenKind) -> Option<T>,
        e: ErrorKind,
    ) -> Result<T> {
        if let Some(t) = predicate(self.peek()) {
            self.advance();
            Ok(t)
        } else {
            Err(e.into())
        }
    }

    fn peek(&self) -> &TokenKind {
        self.cursor.peek()
    }

    fn peek_next(&self) -> &TokenKind {
        self.cursor.peek_next()
    }

    fn is_at_end(&self) -> bool {
        self.peek() == &TokenKind::Eof
    }
}

impl Parse for Stmt {
    fn parse(parser: &mut Parser) -> Result<Stmt> {
        if parser.matches::<Ident>() && parser.matches_next::<AssignmentOperator>() {
            Ok(Stmt::VarDecl(parser.parse()?))
        } else if parser.matches_token(TokenKind::Keyword(Keyword::LocalVar))
            || parser.matches_token(TokenKind::Keyword(Keyword::GlobalVar))
        {
            Ok(Stmt::VarScopeDecl(parser.parse()?))
        } else if parser.matches_token(TokenKind::Keyword(Keyword::Function)) {
            Ok(Stmt::FnDecl(parser.parse()?))
        } else if parser.matches_token(TokenKind::Keyword(Keyword::While)) {
            Ok(Stmt::While(parser.parse()?))
        } else if parser.matches_token(TokenKind::LeftBrace) {
            Ok(Stmt::Block(parser.parse()?))
        } else if parser.matches_token(TokenKind::Keyword(Keyword::Return)) {
            Ok(Stmt::Return(parser.parse()?))
        } else if parser.matches_token(TokenKind::Keyword(Keyword::Include)) {
            Ok(Stmt::Include(parser.parse()?))
        } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Break)) {
            parser.consume(TokenKind::Semicolon)?;
            Ok(Stmt::Break)
        } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Continue)) {
            parser.consume(TokenKind::Semicolon)?;
            Ok(Stmt::Continue)
        } else if parser.consume_if_matches(TokenKind::Semicolon) {
            Ok(Stmt::NoOp)
        } else {
            let expr = parser.parse()?;
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
            stmts.push(parser.parse_span()?);
        }
        Ok(Block { items: stmts })
    }
}

impl<T: Parse> Parse for OptionalBlock<T> {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if parser.matches_token(TokenKind::LeftBrace) {
            Ok(OptionalBlock::Block(parser.parse()?))
        } else {
            // Parse omitted {}: Only a single T is allowed
            Ok(OptionalBlock::Single(parser.parse()?))
        }
    }
}

impl Parse for Include {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::Include))?;
        parser.consume(TokenKind::LeftParen)?;
        let path = parser.parse()?;
        parser.consume(TokenKind::RightParen)?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(Include { path })
    }
}

impl Matches for VarDecl {
    fn matches(p: &impl Peek) -> bool {
        p.matches::<Ident>() && p.matches_next::<AssignmentOperator>()
    }
}

impl Parse for VarDecl {
    fn parse(parser: &mut Parser) -> Result<VarDecl> {
        let ident = parser.parse()?;
        let operator = AssignmentOperator::parse(parser)?;
        let expr = parser.parse()?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(VarDecl {
            ident,
            expr,
            operator,
        })
    }
}

impl Parse for VarScopeDecl {
    fn parse(parser: &mut Parser) -> Result<VarScopeDecl> {
        let scope = if parser.consume_if_matches(TokenKind::Keyword(Keyword::LocalVar)) {
            VarScope::Local
        } else {
            parser.consume(TokenKind::Keyword(Keyword::GlobalVar))?;
            VarScope::Global
        };
        let ident = parser.parse()?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(VarScopeDecl { ident, scope })
    }
}

impl Parse for FnDecl {
    fn parse(parser: &mut Parser) -> Result<FnDecl> {
        parser.consume(TokenKind::Keyword(Keyword::Function))?;
        let fn_name = parser.parse()?;
        let args = parser.parse()?;
        let block = parser.parse()?;
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
        let expr = parser.parse()?;
        parser.consume(TokenKind::Semicolon)?;
        Ok(Return { expr })
    }
}

impl Parse for While {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::While))?;
        parser.consume(TokenKind::LeftParen)?;
        let condition = parser.parse()?;
        parser.consume(TokenKind::RightParen)?;
        let block = parser.parse::<OptionalBlock<_>>()?.into();
        Ok(While { condition, block })
    }
}

impl Parse for Expr {
    fn parse(parser: &mut Parser) -> Result<Expr> {
        pratt_parse_expr(parser, 0)
    }
}

fn pratt_parse_expr(parser: &mut Parser, min_bp: usize) -> Result<Expr> {
    let mut lhs = if parser.matches::<Atom>() {
        Expr::Atom(parser.parse()?)
    } else if parser.consume_if_matches(TokenKind::LeftParen) {
        let lhs = pratt_parse_expr(parser, 0)?;
        parser.consume(TokenKind::RightParen)?;
        lhs
    } else if parser.matches::<UnaryPrefixOperator>() {
        let op: UnaryPrefixOperator = parser.parse()?;
        let r_bp = op.right_binding_power();
        Expr::Unary(Unary {
            op: UnaryOperator::Prefix(op),
            rhs: Box::new(pratt_parse_expr(parser, r_bp)?),
        })
    } else {
        Err(ErrorKind::ExpressionExpected)?
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
            parser.parse::<UnaryPostfixOperator>().unwrap();
            lhs = Expr::Unary(Unary {
                op: UnaryOperator::Postfix(op),
                rhs: Box::new(lhs),
            });
            continue;
        }
        let op = BinaryOperator::peek_parse(parser)
            .ok_or_else(|| ErrorKind::TokenExpected(TokenKind::Semicolon))?;
        let (l_bp, r_bp) = op.binding_power();
        if l_bp < min_bp {
            break;
        }
        let _: BinaryOperator = parser.parse().unwrap();
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
        if parser.matches::<Literal>() {
            Ok(Atom::Literal(parser.parse().unwrap()))
        } else if parser.matches_token(TokenKind::LeftBracket) {
            Ok(Atom::Array(parser.parse()?))
        } else {
            let ident = parser.parse()?;
            if parser.consume_if_matches(TokenKind::LeftBracket) {
                let index_expr = Box::new(parser.parse()?);
                parser.consume(TokenKind::RightBracket)?;
                Ok(Atom::ArrayAccess(ArrayAccess { index_expr, ident }))
            } else if parser.matches_token(TokenKind::LeftParen) {
                Ok(Atom::FnCall(FnCall {
                    fn_name: ident,
                    args: parser.parse()?,
                }))
            } else {
                Ok(Atom::Ident(ident))
            }
        }
    }
}

impl Matches for Atom {
    fn matches(parser: &impl Peek) -> bool {
        parser.matches::<Ident>()
            || parser.matches::<Literal>()
            || parser.peek() == &TokenKind::LeftBracket
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
                parser
                    .parse()
                    .map_err(|_| ErrorKind::TokenExpected(Delim::end()))?,
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
        if parser.matches::<Ident>() && parser.next_matches_token(TokenKind::DoublePoint) {
            let ident = parser.parse()?;
            parser.consume(TokenKind::DoublePoint)?;
            let expr = Box::new(parser.parse()?);
            Ok(FnArg::Named(NamedFnArg { ident, expr }))
        } else {
            let expr = Box::new(parser.parse()?);
            Ok(FnArg::Anonymous(AnonymousFnArg { expr }))
        }
    }
}

impl Parse for Array {
    fn parse(parser: &mut Parser) -> Result<Self> {
        Ok(Array {
            items: parser.parse()?,
        })
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
            fn matches(parser: &impl Peek) -> bool {
                matches!(parser.peek(), TokenKind::$kind(_))
            }
        }
    };
}

impl_trivial_parse!(Ident, Ident, ErrorKind::IdentExpected);
impl_trivial_parse!(Literal, Literal, ErrorKind::LiteralExpected);
