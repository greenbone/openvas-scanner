use std::vec;

use super::{ParseErrorKind, Parser};
use crate::nasl::syntax::token::{self, Literal, TokenKind};

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
pub struct VariableDecl {
    pub ident: Ident,
    pub operator: AssignmentOperator,
    pub expr: Expr,
}

#[derive(Clone, Debug)]
pub struct FunctionDecl;

#[derive(Clone, Debug)]
pub enum Declaration {
    Stmt(Stmt),
    VariableDecl(VariableDecl),
    FunctionDecl(FunctionDecl),
}

#[derive(Clone, Debug)]
pub enum Stmt {
    ExprStmt(Expr),
}

#[derive(Clone, Debug)]
pub enum Expr {
    Grouping(Grouping),
    Unary(Unary),
    Binary(Binary),
    Literal(Literal),
    Ident(Ident),
}

#[derive(Clone, Debug)]
pub struct Grouping {
    pub expr: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct Unary {
    pub operator: UnaryOperator,
    pub right: Box<Expr>,
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
            type Output = $ty;

            fn parse(parser: &mut Parser) -> Result<Self::Output, ParseErrorKind> {
                parser.consume_pat(Self::convert, $err)
            }
        }

    }
}

make_operator! {
    UnaryOperator,
    ParseErrorKind::ExpectedUnaryOperator,
    (
        Minus,
        Bang,
        Plus,
        Tilde,
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
        AmpersandAmpersand,
        PipePipe,
    )
}

#[derive(Clone, Debug)]
pub struct Binary {
    pub left: Box<Expr>,
    pub operator: BinaryOperator,
    pub right: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct Ident {
    pub ident: token::Ident,
}
