mod cursor;
mod error;
pub mod grammar;
#[cfg(test)]
mod tests;

use cursor::Cursor;
use cursor::Peek;
pub use error::ErrorKind as ParseErrorKind;
pub use error::SpannedError as ParseError;
use error::SpannedError;
use error::{Error, ErrorKind};
use grammar::ArrayAccess;
use grammar::Assignment;
use grammar::AssignmentOperator;
use grammar::BinaryOrAssignmentOperator;
use grammar::Exit;
use grammar::FnCall;
use grammar::For;
use grammar::Foreach;
use grammar::If;
use grammar::Increment;
use grammar::IncrementKind;
use grammar::IncrementOperator;
use grammar::PlaceExpr;
use grammar::Repeat;
use grammar::UnaryPrefixOperatorWithIncrement;
use grammar::x_binding_power;

use crate::nasl::error::Span;

use super::{Ident, Keyword, Token, TokenKind, Tokenizer, token::Literal};
use grammar::{
    AnonymousFnArg, Array, Ast, Atom, Binary, BinaryOperator, Block, CommaSeparated, Expr, FnArg,
    FnDecl, Include, NamedFnArg, Return, Stmt, Unary, UnaryPostfixOperator, VarScope, VarScopeDecl,
    While,
};

type Result<T, E = Error> = std::result::Result<T, E>;

trait Parse: Sized {
    fn parse(parser: &mut Parser) -> Result<Self>;
}

trait Matches: Sized {
    fn matches(p: &impl Peek) -> bool;
}

trait FromPeek: Sized {
    fn from_peek(p: &impl Peek) -> Option<Self>;
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

impl Peek for Parser {
    fn peek(&self) -> &TokenKind {
        self.cursor.peek()
    }

    fn peek_next(&self) -> &TokenKind {
        self.cursor.peek_next()
    }
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
            // Check if any tokenization errors occurred, those have priority
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
            if let TokenKind::Keyword(Keyword::LocalVar) = self.peek() {
                return;
            }
        }
    }

    fn parse<T: Parse>(&mut self) -> Result<T> {
        T::parse(self)
    }

    fn advance(&mut self) -> Token {
        self.cursor.advance()
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

    fn is_at_end(&self) -> bool {
        self.peek() == &TokenKind::Eof
    }
}

fn parse_stmt_without_semicolon(parser: &mut Parser) -> Result<Stmt> {
    if parser.matches::<VarScope>() {
        Ok(Stmt::VarScopeDecl(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Function)) {
        Ok(Stmt::FnDecl(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::While)) {
        Ok(Stmt::While(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Repeat)) {
        Ok(Stmt::Repeat(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::ForEach)) {
        Ok(Stmt::Foreach(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::For)) {
        Ok(Stmt::For(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::If)) {
        Ok(Stmt::If(parser.parse()?))
    } else if parser.token_matches(TokenKind::LeftBrace) {
        Ok(Stmt::Block(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Return)) {
        Ok(Stmt::Return(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Include)) {
        Ok(Stmt::Include(parser.parse()?))
    } else if parser.token_matches(TokenKind::Keyword(Keyword::Exit)) {
        Ok(Stmt::Exit(parser.parse()?))
    } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Break)) {
        Ok(Stmt::Break)
    } else if parser.consume_if_matches(TokenKind::Keyword(Keyword::Continue)) {
        Ok(Stmt::Continue)
    } else if parser.token_matches(TokenKind::Semicolon) {
        Ok(Stmt::NoOp)
    } else {
        let expr = parser.parse()?;
        Ok(Stmt::ExprStmt(expr))
    }
}

impl Parse for Stmt {
    fn parse(parser: &mut Parser) -> Result<Stmt> {
        let stmt = parse_stmt_without_semicolon(parser)?;
        match stmt {
            Stmt::VarScopeDecl(_)
            | Stmt::ExprStmt(_)
            | Stmt::Repeat(_)
            | Stmt::Include(_)
            | Stmt::Exit(_)
            | Stmt::Return(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::NoOp => parser.consume(TokenKind::Semicolon)?,
            Stmt::FnDecl(_)
            | Stmt::Block(_)
            | Stmt::While(_)
            | Stmt::Foreach(_)
            | Stmt::For(_)
            | Stmt::If(_) => {}
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
            stmts.push(parser.parse_span()?);
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
        let path = parser.parse()?;
        parser.consume(TokenKind::RightParen)?;
        Ok(Include { path })
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
        let initializer = Box::new(parser.parse()?);
        let condition = parser.parse()?;
        parser.consume(TokenKind::Semicolon)?;
        // The last statement probably doesn't have a trailing
        // semicolon, so we cannot use parser.parse::<Stmt>() here.
        let increment = Box::new(parse_stmt_without_semicolon(parser)?);
        parser.consume(TokenKind::RightParen)?;
        let block = parser.parse::<OptionalBlock<_>>()?.into();
        Ok(For {
            initializer,
            condition,
            increment,
            block,
        })
    }
}

impl Parse for Foreach {
    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.consume(TokenKind::Keyword(Keyword::ForEach))?;
        let var = parser.parse()?;
        parser.consume(TokenKind::LeftParen)?;
        let array = parser.parse()?;
        parser.consume(TokenKind::RightParen)?;
        let block = parser.parse::<OptionalBlock<_>>()?.into();
        Ok(Foreach { array, block, var })
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
    let mut lhs = if parser.matches::<Atom>() {
        Expr::Atom(parser.parse()?)
    } else if parser.consume_if_matches(TokenKind::LeftParen) {
        let lhs = pratt_parse_expr(parser, 0)?;
        parser.consume(TokenKind::RightParen)?;
        lhs
    } else if parser.matches::<UnaryPrefixOperatorWithIncrement>() {
        let op: UnaryPrefixOperatorWithIncrement = parser.parse()?;
        let r_bp = op.right_binding_power();
        match op {
            UnaryPrefixOperatorWithIncrement::Minus
            | UnaryPrefixOperatorWithIncrement::Bang
            | UnaryPrefixOperatorWithIncrement::Plus
            | UnaryPrefixOperatorWithIncrement::Tilde => Expr::Unary(Unary {
                op: op.into(),
                rhs: Box::new(pratt_parse_expr(parser, r_bp)?),
            }),
            UnaryPrefixOperatorWithIncrement::PlusPlus
            | UnaryPrefixOperatorWithIncrement::MinusMinus => {
                let expr = parser.parse_span()?;
                Expr::Atom(Atom::Increment(Increment {
                    op: op.into(),
                    expr,
                    kind: IncrementKind::Prefix,
                }))
            }
        }
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

        if let Some(op) = parser.parse_from_peek::<UnaryPostfixOperator>() {
            let l_bp = op.left_binding_power();
            if l_bp < min_bp {
                break;
            }
            // We treat [ and ( as postfix operators
            // but "short-circuit" to `ArrayAccess`
            // or `FnCall` respectively, since they
            // have maximal precedence
            lhs = match op {
                UnaryPostfixOperator::PlusPlus | UnaryPostfixOperator::MinusMinus => {
                    let lhs = PlaceExpr::from_expr(lhs)?;
                    // Consume the operator token
                    let op = parser.parse::<IncrementOperator>().unwrap();
                    Expr::Atom(Atom::Increment(Increment {
                        op,
                        expr: lhs,
                        kind: IncrementKind::Postfix,
                    }))
                }
                UnaryPostfixOperator::LeftBracket => {
                    // Consume the [
                    parser.parse::<UnaryPostfixOperator>().unwrap();
                    let index_expr = parser.parse()?;
                    parser.consume(TokenKind::RightBracket)?;
                    Expr::Atom(Atom::ArrayAccess(ArrayAccess {
                        index_expr: Box::new(index_expr),
                        lhs_expr: Box::new(lhs),
                    }))
                }
                UnaryPostfixOperator::LeftParen => {
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
                        fn_expr: Box::new(lhs),
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
            .ok_or(ErrorKind::TokenExpected(TokenKind::Semicolon))?;
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
        if let Expr::Atom(Atom::Ident(ident)) = expr {
            Ok(PlaceExpr {
                ident: ident.clone(),
                array_accesses: vec![],
            })
        } else if let Expr::Atom(Atom::ArrayAccess(array_access)) = expr {
            let mut inner = PlaceExpr::from_expr(*array_access.lhs_expr)?;
            inner
                .array_accesses
                .push((*array_access.index_expr).clone());
            Ok(inner)
        } else {
            Err(ParseErrorKind::NotAllowedInPlaceExpr.into())
        }
    }
}

impl Parse for PlaceExpr {
    fn parse(parser: &mut Parser) -> Result<Self> {
        let expr = Expr::parse(parser)?;
        Self::from_expr(expr)
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
        if parser.matches::<Ident>() && parser.next_token_matches(TokenKind::DoublePoint) {
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

macro_rules! impl_multi_token_parse {
    ($ty: ty, ($($kind: expr => $expr: expr),*$(,)?)) => {
        impl Parse for $ty {
            fn parse(parser: &mut Parser) -> Result<Self> {
                $(
                    if parser.consume_if_matches($kind) {
                        return Ok($expr);
                    }
                )*
                Err(ParseErrorKind::TokensExpected(vec![
                    $( $kind ),*
                ]).into())
            }
        }

        impl Matches for $ty {
            fn matches(p: &impl Peek) -> bool {
                let kind = p.peek();
                $(
                    if *kind == $kind {
                        return true
                    }
                )*
                false
            }
        }
    }
}

impl_multi_token_parse!(VarScope, (
    TokenKind::Keyword(Keyword::LocalVar) => Self::Local,
    TokenKind::Keyword(Keyword::GlobalVar) => Self::Global,
));
