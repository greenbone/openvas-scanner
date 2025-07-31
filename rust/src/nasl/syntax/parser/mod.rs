pub mod cursor;
pub mod error;
mod pretty_print;
#[cfg(test)]
mod tests;

use error::ErrorKind as ParseErrorKind;
pub use error::SpannedError as ParseError;
use error::SpannedError;
pub use error::{Error, ErrorKind};

use super::CharIndex;
use super::grammar::ArrayAccess;
use super::grammar::Assignment;
use super::grammar::AssignmentOperator;
use super::grammar::BinaryOrAssignmentOperator;
use super::grammar::Exit;
use super::grammar::FnCall;
use super::grammar::For;
use super::grammar::ForEach;
use super::grammar::If;
use super::grammar::Increment;
use super::grammar::IncrementKind;
use super::grammar::IncrementOperator;
use super::grammar::PlaceExpr;
use super::grammar::Repeat;
use super::grammar::UnaryPostfixOperatorKind;
use super::grammar::UnaryPrefixOperatorWithIncrement;
use super::grammar::UnaryPrefixOperatorWithIncrementKind;
use super::grammar::x_binding_power;
use super::grammar::{
    AnonymousFnArg, Array, Ast, Atom, Binary, BinaryOperator, Block, CommaSeparated, Expr, FnArg,
    FnDecl, Include, NamedFnArg, Return, Statement, Unary, UnaryPostfixOperator, VarScope,
    VarScopeDecl, While,
};
use super::token::LiteralKind;
use super::{Ident, Keyword, Token, TokenKind, Tokenizer, token::Literal};
use crate::nasl::error::Span;
use crate::nasl::error::Spanned;
use crate::nasl::syntax::grammar::UnaryPrefixOperatorKind;
use cursor::Cursor;
use cursor::Peek;

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait Parse: Sized {
    fn parse(parser: &mut Parser) -> Result<Self>;
}

pub trait Matches: Sized {
    fn matches(p: &impl Peek) -> bool;
}

pub trait FromPeek: Sized {
    fn from_peek(p: &impl Peek) -> Option<Self>;
}

pub trait Delimiter: Default {
    fn start() -> TokenKind;
    fn end() -> TokenKind;
}

enum OptionalBlock<T> {
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
    errors: Vec<SpannedError>,
}

impl Peek for Parser {
    fn peek(&self) -> &TokenKind {
        self.cursor.peek()
    }

    fn peek_next(&self) -> &TokenKind {
        self.cursor.peek_next()
    }

    fn token_span(&self) -> Span {
        self.cursor.token_span()
    }
}

struct PositionMarker {
    pos: CharIndex,
}

impl Parser {
    pub fn new(tokenizer: Tokenizer) -> Self {
        Self {
            cursor: Cursor::new(tokenizer).unwrap(),
            errors: vec![],
        }
    }

    pub fn parse_span<T: Parse>(&mut self) -> Result<T> {
        let pos_before = self.cursor.current_token_start();
        let result = self.parse();
        let pos_after = self.cursor.previous_token_end();
        let span = Span::new(pos_before, pos_after);
        result.map_err(|err| err.with_span(&span))
    }

    fn check_tokenizer_errors(&mut self) -> bool {
        if self.cursor.has_errors() {
            self.errors
                .extend(self.cursor.drain_all_errors().map(|e| e.into()));
            self.synchronize();
            true
        } else {
            false
        }
    }

    pub fn parse_program(mut self) -> Result<Ast, Vec<SpannedError>> {
        let mut stmts = vec![];
        while !self.is_at_end() {
            let result = self.parse_span::<Statement>();
            // Check if any tokenization errors occurred, those have priority
            // and make the actual result obtained from parsing void
            if !self.check_tokenizer_errors() {
                match result {
                    Ok(decl) => stmts.push(decl),
                    Err(err) => {
                        // We know the error has a span since it originates from
                        // parse_span
                        self.errors.push(err.unwrap_as_spanned());
                        self.synchronize();
                    }
                }
            }
        }
        self.check_tokenizer_errors();
        if self.errors.is_empty() {
            Ok(Ast::new(stmts))
        } else {
            let mut errors = self.errors;
            if errors
                .iter()
                .any(|e| matches!(e.kind, ErrorKind::Tokenizer(_)))
            {
                // Don't show any parsing errors if there were tokenization errors.
                errors.retain(|e| matches!(e.kind, ErrorKind::Tokenizer(_)));
            }
            Err(errors)
        }
    }

    fn synchronize(&mut self) {
        while !self.is_at_end() {
            let token = self.peek();
            if matches!(token, TokenKind::Semicolon) {
                self.advance();
                return;
            }
            if matches!(
                token,
                TokenKind::Keyword(Keyword::LocalVar)
                    | TokenKind::Keyword(Keyword::GlobalVar)
                    | TokenKind::Keyword(Keyword::Return)
                    | TokenKind::Keyword(Keyword::Exit)
                    | TokenKind::Keyword(Keyword::ForEach)
                    | TokenKind::Keyword(Keyword::For)
                    | TokenKind::Keyword(Keyword::Repeat)
                    | TokenKind::Keyword(Keyword::While)
                    | TokenKind::LeftBrace
                    | TokenKind::RightBrace
            ) {
                return;
            }
            self.advance();
        }
    }

    fn peek_span(&self) -> Span {
        self.cursor.peek_span()
    }

    pub fn parse<T: Parse>(&mut self) -> Result<T> {
        T::parse(self)
    }

    pub fn advance(&mut self) -> Token {
        let token = self.cursor.advance();
        self.check_tokenizer_errors();
        token
    }

    fn consume_if_matches(&mut self, expected: TokenKind) -> bool {
        self.consume(expected).is_ok()
    }

    fn consume(&mut self, expected: TokenKind) -> Result<()> {
        if self.peek() != &expected {
            let err: Error = ErrorKind::TokenExpected(expected).into();
            Err(err.with_span(&self.cursor.span_previous_token_end()))
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

    fn is_at_end(&self) -> bool {
        self.peek() == &TokenKind::Eof
    }

    fn remember_pos(&self) -> PositionMarker {
        PositionMarker {
            pos: self.cursor.current_token_start(),
        }
    }

    fn make_span(&self, pos: PositionMarker) -> Span {
        if pos.pos == self.cursor.current_token_start() {
            Span::new(
                self.cursor.current_token_start(),
                self.cursor.current_token_end(),
            )
        } else {
            Span::new(pos.pos, self.cursor.previous_token_end())
        }
    }

    fn error(&self, start: PositionMarker, kind: ParseErrorKind) -> Error {
        let err: Error = kind.into();
        err.with_span(&self.make_span(start))
    }
}

fn parse_stmt_without_semicolon(parser: &mut Parser) -> Result<Statement> {
    if parser.matches::<VarScope>() {
        Ok(Statement::VarScopeDecl(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Function)) {
        Ok(Statement::FnDecl(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::While)) {
        Ok(Statement::While(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Repeat)) {
        Ok(Statement::Repeat(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::ForEach)) {
        Ok(Statement::ForEach(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::For)) {
        Ok(Statement::For(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::If)) {
        Ok(Statement::If(parser.parse()?))
    } else if parser.token_matches(TokenKind::LeftBrace) {
        Ok(Statement::Block(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Return)) {
        Ok(Statement::Return(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Include)) {
        Ok(Statement::Include(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Exit)) {
        Ok(Statement::Exit(parser.parse()?))
    } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Break)) {
        Ok(Statement::Break)
    } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Continue)) {
        Ok(Statement::Continue)
    } else if parser.token_matches(TokenKind::Semicolon) {
        Ok(Statement::NoOp)
    } else {
        let expr = parser.parse()?;
        Ok(Statement::ExprStmt(expr))
    }
}

impl Parse for Statement {
    fn parse(parser: &mut Parser) -> Result<Statement> {
        let stmt = parse_stmt_without_semicolon(parser)?;
        match stmt {
            Statement::VarScopeDecl(_)
            | Statement::ExprStmt(_)
            | Statement::Repeat(_)
            | Statement::Include(_)
            | Statement::Exit(_)
            | Statement::Return(_)
            | Statement::Break
            | Statement::Continue
            | Statement::NoOp => parser.consume(TokenKind::Semicolon)?,
            Statement::FnDecl(_)
            | Statement::Block(_)
            | Statement::While(_)
            | Statement::ForEach(_)
            | Statement::For(_)
            | Statement::If(_) => {}
        }
        Ok(stmt)
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
            let result = parser.parse_span();
            match result {
                Ok(stmt) => stmts.push(stmt),
                Err(err) => {
                    parser.errors.push(err.unwrap_as_spanned());
                    parser.synchronize();
                    if parser.token_matches(TokenKind::Eof) {
                        return Err(parser.consume(TokenKind::RightBrace).unwrap_err());
                    }
                }
            }
        }
        Ok(Block { items: stmts })
    }
}

impl<T: Parse> Parse for OptionalBlock<T> {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if parser.token_matches(TokenKind::LeftBrace) {
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
        let path: Literal = parser.parse()?;
        let span = parser.peek_span();
        if !matches!(path.kind, LiteralKind::String(_) | LiteralKind::Data(_)) {
            let error: Error = ErrorKind::StringExpected.into();
            return Err(error.with_span(&span));
        }
        let path = path.into_string().unwrap();
        parser.consume(TokenKind::RightParen)?;
        Ok(Include { path, span })
    }
}

impl Parse for Exit {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::Exit))?;
        parser.consume(TokenKind::LeftParen)?;
        let expr = parser.parse()?;
        parser.consume(TokenKind::RightParen)?;
        Ok(Exit { expr })
    }
}

impl Parse for VarScopeDecl {
    fn parse(parser: &mut Parser) -> Result<VarScopeDecl> {
        let scope = parser.parse()?;
        let mut idents = vec![];
        idents.push(parser.parse()?);
        while parser.consume_if_matches(TokenKind::Comma) {
            idents.push(parser.parse()?);
        }
        Ok(VarScopeDecl { idents, scope })
    }
}

impl Parse for VarScope {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if parser.consume_if_matches(TokenKind::Keyword(Keyword::LocalVar)) {
            return Ok(Self::Local);
        }
        if parser.consume_if_matches(TokenKind::Keyword(Keyword::GlobalVar)) {
            return Ok(Self::Global);
        }
        Err(ParseErrorKind::TokensExpected(vec![
            TokenKind::Keyword(Keyword::LocalVar),
            TokenKind::Keyword(Keyword::GlobalVar),
        ])
        .into())
    }
}
impl Matches for VarScope {
    fn matches(p: &impl Peek) -> bool {
        let kind = p.peek();
        if *kind == (TokenKind::Keyword(Keyword::LocalVar)) {
            return true;
        }
        if *kind == (TokenKind::Keyword(Keyword::GlobalVar)) {
            return true;
        }
        false
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
        let expr = if parser.token_matches(TokenKind::Semicolon) {
            None
        } else {
            Some(parser.parse()?)
        };
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

impl Parse for Repeat {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::Repeat))?;
        let block = parser.parse::<OptionalBlock<_>>()?;
        // If we parse a single stmt and the {} are omitted,
        // then the semicolon is parsed as part of the single
        // statement, so we don't check for another one.
        if matches!(block, OptionalBlock::Block(_)) {
            parser.consume_if_matches(TokenKind::Semicolon);
        }
        parser.consume(TokenKind::Keyword(Keyword::Until))?;
        let has_paren = parser.consume_if_matches(TokenKind::LeftParen);
        let condition = parser.parse()?;
        if has_paren {
            parser.consume(TokenKind::RightParen)?;
        }
        Ok(Repeat {
            condition,
            block: block.into(),
        })
    }
}

impl Parse for For {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::For))?;
        parser.consume(TokenKind::LeftParen)?;
        let initializer = if parser.consume_if_matches(TokenKind::Semicolon) {
            None
        } else {
            Some(Box::new(parser.parse()?))
        };
        let condition = parser.parse()?;
        parser.consume(TokenKind::Semicolon)?;
        // The last statement probably doesn't have a trailing
        // semicolon, so we cannot use parser.parse::<Stmt>() here.
        let increment = if parser.consume_if_matches(TokenKind::Semicolon) {
            parser.consume(TokenKind::RightParen)?;
            None
        } else if parser.consume_if_matches(TokenKind::RightParen) {
            None
        } else {
            let increment = Some(Box::new(parse_stmt_without_semicolon(parser)?));
            parser.consume(TokenKind::RightParen)?;
            increment
        };
        let block = parser.parse::<OptionalBlock<_>>()?.into();
        Ok(For {
            initializer,
            condition,
            increment,
            block,
        })
    }
}

impl Parse for ForEach {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::ForEach))?;
        let var = parser.parse()?;
        parser.consume(TokenKind::LeftParen)?;
        let array = parser.parse()?;
        parser.consume(TokenKind::RightParen)?;
        let block = parser.parse::<OptionalBlock<_>>()?.into();
        Ok(ForEach { array, block, var })
    }
}

impl Parse for If {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::If))?;
        parser.consume(TokenKind::LeftParen)?;
        let condition = parser.parse()?;
        parser.consume(TokenKind::RightParen)?;
        let block = parser.parse::<OptionalBlock<_>>()?.into();
        let mut if_branches = vec![(condition, block)];
        let mut else_branch = None;
        while parser.consume_if_matches(TokenKind::Keyword(Keyword::Else)) {
            if parser.consume_if_matches(TokenKind::Keyword(Keyword::If)) {
                parser.consume(TokenKind::LeftParen)?;
                let condition = parser.parse()?;
                parser.consume(TokenKind::RightParen)?;
                let block = parser.parse::<OptionalBlock<_>>()?.into();
                if_branches.push((condition, block));
            } else {
                else_branch = Some(parser.parse::<OptionalBlock<_>>()?.into());
                break;
            }
        }
        Ok(If {
            if_branches,
            else_branch,
        })
    }
}

impl Parse for Expr {
    fn parse(parser: &mut Parser) -> Result<Expr> {
        pratt_parse_expr(parser, 0)
    }
}

fn pratt_parse_expr(parser: &mut Parser, min_bp: usize) -> Result<Expr> {
    let start = parser.remember_pos();
    let mut lhs = if parser.matches::<Atom>() {
        Expr::Atom(parser.parse()?)
    } else if parser.consume_if_matches(TokenKind::LeftParen) {
        let lhs = pratt_parse_expr(parser, 0)?;
        parser.consume(TokenKind::RightParen)?;
        lhs
    } else if parser.matches::<UnaryPrefixOperatorWithIncrement>() {
        let op: UnaryPrefixOperatorWithIncrement = parser.parse()?;
        let r_bp = op.right_binding_power();
        match op.kind {
            UnaryPrefixOperatorWithIncrementKind::Minus
            | UnaryPrefixOperatorWithIncrementKind::Bang
            | UnaryPrefixOperatorWithIncrementKind::Plus
            | UnaryPrefixOperatorWithIncrementKind::Tilde => Expr::Unary(Unary {
                op: op.into(),
                rhs: Box::new(pratt_parse_expr(parser, r_bp)?),
            }),
            UnaryPrefixOperatorWithIncrementKind::PlusPlus
            | UnaryPrefixOperatorWithIncrementKind::MinusMinus => {
                let expr = pratt_parse_expr(parser, r_bp)?;
                let expr = PlaceExpr::from_expr(expr)?;
                Expr::Atom(Atom::Increment(Increment {
                    op: op.into(),
                    expr,
                    kind: IncrementKind::Prefix,
                }))
            }
        }
    } else {
        return Err(parser.error(start, ErrorKind::ExpressionExpected));
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

        if let Some(op) = parser.parse_from_peek::<UnaryPostfixOperator>() {
            let l_bp = op.left_binding_power();
            if l_bp < min_bp {
                break;
            }
            // We treat [ and ( as postfix operators
            // but "short-circuit" to `ArrayAccess`
            // or `FnCall` respectively, since they
            // have maximal precedence
            lhs = match op.kind {
                UnaryPostfixOperatorKind::PlusPlus | UnaryPostfixOperatorKind::MinusMinus => {
                    let lhs = PlaceExpr::from_expr(lhs)?;
                    // Consume the operator token
                    let op = parser.parse::<IncrementOperator>().unwrap();
                    Expr::Atom(Atom::Increment(Increment {
                        op,
                        expr: lhs,
                        kind: IncrementKind::Postfix,
                    }))
                }
                UnaryPostfixOperatorKind::LeftBracket => {
                    // Consume the [
                    parser.parse::<UnaryPostfixOperator>().unwrap();
                    let index_expr = parser.parse()?;
                    parser.consume(TokenKind::RightBracket)?;
                    Expr::Atom(Atom::ArrayAccess(ArrayAccess {
                        index_expr: Box::new(index_expr),
                        lhs_expr: Box::new(lhs),
                    }))
                }
                UnaryPostfixOperatorKind::LeftParen => {
                    // Here, we don't consume the ( since that
                    // is taken care of by CommaSeparated::parse
                    let args = parser.parse()?;
                    // We take the precedence of the X operator to be maximal,
                    // in order not to overcomplicate things.
                    let num_repeats = if parser.consume_if_matches(TokenKind::X) {
                        Some(Box::new(pratt_parse_expr(parser, x_binding_power())?))
                    } else {
                        None
                    };
                    Expr::Atom(Atom::FnCall(FnCall {
                        fn_name: Ident::from_expr(lhs)?,
                        args,
                        num_repeats,
                    }))
                }
            };
            continue;
        }

        // Handle binary operators and assignment separately, so
        // that we're able to verify that the LHS is a valid
        // place expression.
        let op = parser
            .parse_from_peek::<BinaryOrAssignmentOperator>()
            .ok_or_else(|| parser.consume(TokenKind::Semicolon).unwrap_err())?;
        let (l_bp, r_bp) = op.binding_power();
        if l_bp < min_bp {
            break;
        }
        lhs = match op {
            BinaryOrAssignmentOperator::Binary(_) => {
                let op: BinaryOperator = parser.parse().unwrap();
                let rhs = pratt_parse_expr(parser, r_bp)?;
                Expr::Binary(Binary {
                    lhs: Box::new(lhs),
                    op,
                    rhs: Box::new(rhs),
                })
            }
            BinaryOrAssignmentOperator::Assignment(_) => {
                let place_expr = Box::new(PlaceExpr::from_expr(lhs)?);
                let op: AssignmentOperator = parser.parse().unwrap();
                let rhs = pratt_parse_expr(parser, r_bp)?;
                Expr::Assignment(Assignment {
                    lhs: place_expr,
                    op,
                    rhs: Box::new(rhs),
                })
            }
        }
    }
    Ok(lhs)
}

impl Parse for Atom {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if parser.matches::<Literal>() {
            Ok(Atom::Literal(parser.parse().unwrap()))
        } else if parser.token_matches(TokenKind::LeftBracket) {
            Ok(Atom::Array(parser.parse()?))
        } else {
            let ident = parser.parse()?;
            Ok(Atom::Ident(ident))
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

impl PlaceExpr {
    fn from_expr(expr: Expr) -> Result<Self> {
        let span = expr.span();
        let make_err = || {
            let err: Error = ParseErrorKind::NotAllowedInPlaceExpr.into();
            Err(err.with_span(&span))
        };
        if let Expr::Atom(Atom::Ident(ident)) = expr {
            Ok(PlaceExpr {
                ident: ident.clone(),
                array_accesses: vec![],
                negate: false,
            })
        } else if let Expr::Atom(Atom::ArrayAccess(array_access)) = expr {
            let mut inner = PlaceExpr::from_expr(*array_access.lhs_expr)?;
            inner
                .array_accesses
                .push((*array_access.index_expr).clone());
            Ok(inner)
        } else if let Expr::Unary(unary) = expr {
            let mut place_expr = PlaceExpr::from_expr(*unary.rhs)?;
            if let UnaryPrefixOperatorKind::Bang = unary.op.kind {
                place_expr.negate = true
            } else {
                return make_err();
            }
            Ok(place_expr)
        } else {
            make_err()
        }
    }
}

impl<Item: Parse, Delim: Delimiter> Parse for CommaSeparated<Item, Delim> {
    fn parse(parser: &mut Parser) -> Result<Self> {
        let pos = parser.remember_pos();
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
        let span = parser.make_span(pos);
        Ok(CommaSeparated::new(items, span))
    }
}

impl Parse for FnArg {
    fn parse(parser: &mut Parser) -> Result<Self> {
        if parser.matches::<Ident>() && parser.next_token_matches(TokenKind::Colon) {
            let ident = parser.parse()?;
            parser.consume(TokenKind::Colon)?;
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

impl Ident {
    pub(crate) fn from_expr(lhs: super::grammar::Expr) -> Result<Ident> {
        if let Expr::Atom(Atom::Ident(ident)) = lhs {
            Ok(ident)
        } else {
            Err(ErrorKind::IdentExpected.into())
        }
    }
}
