use std::vec;

use super::{ParseErrorKind, Parser};
use crate::nasl::syntax::token::{Ident, Literal, TokenKind};

#[derive(Clone, Debug)]
pub struct Ast {
    stmts: Vec<Declaration>,
    position: usize,
}

impl IntoIterator for Ast {
    type Item = Declaration;

    type IntoIter = vec::IntoIter<Declaration>;

    fn into_iter(self) -> Self::IntoIter {
        self.stmts.into_iter()
    }
}

impl Ast {
    pub fn new(stmts: Vec<Declaration>) -> Self {
        Self { stmts, position: 0 }
    }

    pub fn decls(self) -> Vec<Declaration> {
        self.stmts
    }

    pub fn next(&mut self) -> Option<Declaration> {
        let stmt = self.stmts.get(self.position);
        self.position += 1;
        stmt.cloned()
    }
}

#[derive(Clone, Debug)]
pub enum Declaration {
    Stmt(Stmt),
    VariableDecl(VariableDecl),
    FunctionDecl(FunctionDecl),
}

#[derive(Clone, Debug)]
pub struct VariableDecl {
    pub ident: Ident,
    pub operator: AssignmentOperator,
    pub expr: Expr,
}

#[derive(Clone, Debug)]
pub struct FunctionDecl;

#[derive(Clone, Debug)]
pub enum Stmt {
    ExprStmt(Expr),
}

#[derive(Clone, Debug)]
pub enum Expr {
    Literal(Literal),
    Ident(Ident),
    Binary(Binary),
    Unary(Unary),
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
            fn peek_parse(parser: &mut Parser) -> Option<Self> {
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
