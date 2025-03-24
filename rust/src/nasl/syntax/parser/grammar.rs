use std::vec;

use super::{ParseErrorKind, Parser};
use crate::nasl::syntax::token::{Ident, Literal, TokenKind};

#[derive(Clone, Debug)]
pub struct Ast {
    stmts: Vec<Stmt>,
    position: usize,
}

impl IntoIterator for Ast {
    type Item = Stmt;

    type IntoIter = vec::IntoIter<Stmt>;

    fn into_iter(self) -> Self::IntoIter {
        self.stmts.into_iter()
    }
}

impl Ast {
    pub fn new(stmts: Vec<Stmt>) -> Self {
        Self { stmts, position: 0 }
    }

    pub fn stmts(self) -> Vec<Stmt> {
        self.stmts
    }

    pub fn next(&mut self) -> Option<Stmt> {
        let stmt = self.stmts.get(self.position);
        self.position += 1;
        stmt.cloned()
    }
}

#[derive(Clone, Debug)]
pub struct CommaSeparated<Item, Delim: Default> {
    pub items: Vec<Item>,
    pub delimiter: Delim,
}

impl<Item, Delim: Default> CommaSeparated<Item, Delim> {
    pub fn new(items: Vec<Item>) -> Self {
        Self {
            items,
            delimiter: Delim::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Stmt {
    VarDecl(VarDecl),
    FnDecl(FnDecl),
    ExprStmt(Expr),
    Block(Block<Stmt>),
    While(While),
    Include(Include),
    Return(Return),
    Break,
    Continue,
    NoOp,
}

#[derive(Clone, Debug)]
pub struct VarDecl {
    pub ident: Ident,
    pub operator: AssignmentOperator,
    pub expr: Expr,
}

#[derive(Clone, Debug)]
pub struct FnDecl {
    pub fn_name: Ident,
    pub args: CommaSeparated<Ident, Paren>,
    pub block: Block<Stmt>,
}

#[derive(Clone, Debug)]
pub struct Return {
    pub expr: Expr,
}

#[derive(Clone, Debug)]
pub struct Block<T> {
    pub items: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct While {
    pub condition: Expr,
    pub block: Block<Stmt>,
}

#[derive(Clone, Debug)]
pub struct Include {
    pub path: Literal,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Atom(Atom),
    Binary(Binary),
    Unary(Unary),
}

#[derive(Clone, Debug)]
pub enum Atom {
    Literal(Literal),
    Ident(Ident),
    Array(Array),
    ArrayAccess(ArrayAccess),
    FnCall(FnCall),
}

#[derive(Clone, Debug)]
pub struct Array {
    pub items: CommaSeparated<Expr, Bracket>,
}

#[derive(Clone, Debug)]
pub struct ArrayAccess {
    pub index_expr: Box<Expr>,
    pub ident: Ident,
}

#[derive(Clone, Debug)]
pub struct FnCall {
    pub fn_name: Ident,
    pub args: CommaSeparated<FnArg, Paren>,
}

#[derive(Clone, Debug)]
pub enum FnArg {
    Anonymous(AnonymousFnArg),
    Named(NamedFnArg),
}

#[derive(Clone, Debug)]
pub struct AnonymousFnArg {
    pub expr: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct NamedFnArg {
    pub ident: Ident,
    pub expr: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct Unary {
    pub op: UnaryOperator,
    pub rhs: Box<Expr>,
}

#[derive(Clone, Debug)]
pub enum UnaryOperator {
    Postfix(UnaryPostfixOperator),
    Prefix(UnaryPrefixOperator),
}

#[derive(Clone, Debug)]
pub struct Binary {
    pub lhs: Box<Expr>,
    pub op: BinaryOperator,
    pub rhs: Box<Expr>,
}

macro_rules! make_operator {
    ($ty: ident, $err: expr, ($($pat: ident$(,)?),*)) => {
        #[derive(Debug, Clone)]
        pub enum $ty {
            $(
                $pat,
            )*
        }

        impl $ty {
            fn convert(kind: &TokenKind) -> Option<Self> {
                match kind {
                    $(
                        TokenKind::$pat => Some(Self::$pat),
                    )*
                    _ => None,
                }
            }
        }

        impl super::Matches for $ty {
            fn matches(kind: &TokenKind) -> bool {
                Self::convert(kind).is_some()
            }
        }

        impl super::Parse for $ty {
            fn parse(parser: &mut Parser) -> Result<$ty, ParseErrorKind> {
                parser.consume_pat(Self::convert, $err)
            }
        }

        impl super::PeekParse for $ty {
            fn peek_parse(parser: &Parser) -> Option<Self> {
                Self::convert(&parser.cursor.peek().kind)
            }
        }

    }
}

make_operator! {
    UnaryPrefixOperator,
    ParseErrorKind::ExpectedUnaryOperator,
    (
        Minus,
        Bang,
        Plus,
        Tilde,
        PlusPlus,
        MinusMinus,
    )
}

make_operator! {
    UnaryPostfixOperator,
    ParseErrorKind::ExpectedUnaryOperator,
    (
        PlusPlus,
        MinusMinus,
    )
}

make_operator! {
    AssignmentOperator,
    ParseErrorKind::ExpectedAssignmentOperator,
    (
        Equal,
        MinusEqual,
        PlusEqual,
        SlashEqual,
        StarEqual,
        GreaterGreaterGreater,
        PercentEqual,
        LessLessEqual,
        GreaterGreaterEqual,
        GreaterGreaterGreaterEqual,
    )
}

make_operator! {
    BinaryOperator,
    ParseErrorKind::ExpectedBinaryOperator,
    (
        Plus,
        Minus,
        Star,
        Slash,
        Percent,
        BangEqual,
        EqualEqual,
        BangTilde,
        EqualTilde,
        Greater,
        GreaterGreater,
        GreaterLess,
        GreaterEqual,
        Less,
        LessLess,
        LessEqual,
        GreaterGreaterGreater,
        GreaterBangLess,
        Ampersand,
        AmpersandAmpersand,
        Caret,
        Pipe,
        PipePipe,
        StarStar,
    )
}

impl BinaryOperator {
    pub fn binding_power(&self) -> (usize, usize) {
        use BinaryOperator::*;
        match self {
            StarStar => (22, 23),
            Star | Slash | Percent => (20, 21),
            Plus | Minus => (18, 19),
            LessLess | GreaterGreater | GreaterGreaterGreater => (16, 17),
            Ampersand => (14, 15),
            Caret => (12, 13),
            Pipe => (10, 11),
            Less | LessEqual | Greater | GreaterEqual | EqualEqual | BangEqual | GreaterLess
            | GreaterBangLess | EqualTilde | BangTilde => (8, 9),
            AmpersandAmpersand => (6, 7),
            PipePipe => (4, 5),
        }
    }
}

impl UnaryPrefixOperator {
    pub fn right_binding_power(&self) -> usize {
        use UnaryPrefixOperator::*;
        match self {
            Plus | Minus | Tilde | Bang | PlusPlus | MinusMinus => 21,
        }
    }
}

impl UnaryPostfixOperator {
    pub fn left_binding_power(&self) -> usize {
        use UnaryPostfixOperator::*;
        match self {
            PlusPlus => 21,
            MinusMinus => 21,
        }
    }
}

macro_rules! make_delimiter {
    ($ty: ident, $start: ident, $end: ident) => {
        #[derive(Clone, Debug, Default)]
        pub struct $ty;

        impl super::Delimiter for $ty {
            fn start() -> TokenKind {
                TokenKind::$start
            }

            fn end() -> TokenKind {
                TokenKind::$end
            }
        }
    };
}

make_delimiter!(Paren, LeftParen, RightParen);
make_delimiter!(Bracket, LeftBracket, RightBracket);
