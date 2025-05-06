use std::vec;

use super::parser::{Error, FromPeek, Parser, cursor::Peek, error::ErrorKind};
use crate::nasl::{
    error::Span,
    syntax::token::{Ident, Literal, TokenKind},
};

#[derive(Clone, Debug)]
pub struct Ast {
    stmts: Vec<Statement>,
    position: usize,
}

impl IntoIterator for Ast {
    type Item = Statement;

    type IntoIter = vec::IntoIter<Statement>;

    fn into_iter(self) -> Self::IntoIter {
        self.stmts.into_iter()
    }
}

impl Ast {
    pub fn new(stmts: Vec<Statement>) -> Self {
        Self { stmts, position: 0 }
    }

    pub fn stmts(self) -> Vec<Statement> {
        self.stmts
    }

    pub fn next_stmt(&mut self) -> Option<Statement> {
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

impl<Item, Delim: Default> AsRef<[Item]> for CommaSeparated<Item, Delim> {
    fn as_ref(&self) -> &[Item] {
        &self.items
    }
}

#[derive(Clone, Debug)]
pub enum Statement {
    VarScopeDecl(VarScopeDecl),
    FnDecl(FnDecl),
    ExprStmt(Expr),
    Block(Block<Statement>),
    While(While),
    Repeat(Repeat),
    Foreach(Foreach),
    For(For),
    If(If),
    Include(Include),
    Exit(Exit),
    Return(Return),
    Break,
    Continue,
    NoOp,
}

#[derive(Clone, Debug)]
pub struct Assignment {
    pub lhs: Box<PlaceExpr>,
    pub op: AssignmentOperator,
    pub rhs: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct PlaceExpr {
    pub ident: Ident,
    pub array_accesses: Vec<Expr>,
}

#[derive(Clone, Debug)]
pub struct VarScopeDecl {
    pub idents: Vec<Ident>,
    pub scope: VarScope,
}

#[derive(Clone, Debug)]
pub enum VarScope {
    Local,
    Global,
}

#[derive(Clone, Debug)]
pub struct FnDecl {
    pub fn_name: Ident,
    pub args: CommaSeparated<Ident, Paren>,
    pub block: Block<Statement>,
}

#[derive(Clone, Debug)]
pub struct Exit {
    pub expr: Expr,
}

#[derive(Clone, Debug)]
pub struct Return {
    pub expr: Option<Expr>,
}

#[derive(Clone, Debug)]
pub struct Block<T> {
    pub items: Vec<T>,
}

#[derive(Clone, Debug)]
pub struct While {
    pub condition: Expr,
    pub block: Block<Statement>,
}

#[derive(Clone, Debug)]
pub struct Repeat {
    pub block: Block<Statement>,
    pub condition: Expr,
}

#[derive(Clone, Debug)]
pub struct Foreach {
    pub var: Ident,
    pub array: Expr,
    pub block: Block<Statement>,
}

#[derive(Clone, Debug)]
pub struct For {
    pub initializer: Option<Box<Statement>>,
    pub condition: Expr,
    pub increment: Option<Box<Statement>>,
    pub block: Block<Statement>,
}

#[derive(Clone, Debug)]
pub struct If {
    pub if_branches: Vec<(Expr, Block<Statement>)>,
    pub else_branch: Option<Block<Statement>>,
}

#[derive(Clone, Debug)]
pub struct Include {
    pub path: String,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Atom(Atom),
    Binary(Binary),
    Unary(Unary),
    // Assignments can appear within expressions.
    Assignment(Assignment),
}

#[derive(Clone, Debug)]
pub enum Atom {
    Literal(Literal),
    Ident(Ident),
    Array(Array),
    ArrayAccess(ArrayAccess),
    FnCall(FnCall),
    Increment(Increment),
}

#[derive(Clone, Debug)]
pub struct Array {
    pub items: CommaSeparated<Expr, Bracket>,
}

#[derive(Clone, Debug)]
pub struct ArrayAccess {
    pub index_expr: Box<Expr>,
    pub lhs_expr: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct FnCall {
    pub fn_name: Ident,
    pub args: CommaSeparated<FnArg, Paren>,
    // We owe this beautiful field to the genius "x" operator.
    pub num_repeats: Option<Box<Expr>>,
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
pub struct Increment {
    pub expr: PlaceExpr,
    pub op: IncrementOperator,
    pub kind: IncrementKind,
}

#[derive(Clone, Debug)]
pub enum IncrementKind {
    Prefix,
    Postfix,
}

#[derive(Clone, Debug)]
pub struct Unary {
    pub op: UnaryPrefixOperator,
    pub rhs: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct Binary {
    pub lhs: Box<Expr>,
    pub op: BinaryOperator,
    pub rhs: Box<Expr>,
}

macro_rules! make_operator {
    ($ty: ident, $err: expr, ($($pat: ident$(,)?),*)) => {
        #[derive(Copy, Debug, Clone, PartialEq)]
        pub enum $ty {
            $(
                $pat,
            )*
        }

        impl super::parser::Matches for $ty {
            fn matches(p: &impl Peek) -> bool {
                p.parse_from_peek::<Self>().is_some()
            }
        }

        impl super::parser::Parse for $ty {
            fn parse(parser: &mut Parser) -> Result<$ty, Error> {
                let converted = parser.parse_from_peek::<Self>();
                if converted.is_some() {
                    parser.advance();
                }
                Ok(converted.ok_or_else(|| $err)?)
            }
        }

        impl super::parser::FromPeek for $ty {
            fn from_peek(p: &impl Peek) -> Option<Self> {
                let kind = p.peek();
                match kind {
                    $(
                        TokenKind::$pat => Some(Self::$pat),
                    )*
                    _ => None,
                }
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$pat => write!(f, "{}", TokenKind::$pat),
                    )*
                }
            }
        }
    }
}

make_operator! {
    UnaryPrefixOperator,
    ErrorKind::ExpectedUnaryOperator,
    (
        Minus,
        Bang,
        Plus,
        Tilde,
    )
}

make_operator! {
    UnaryPrefixOperatorWithIncrement,
    ErrorKind::ExpectedUnaryOperator,
    (
        Minus,
        Bang,
        Plus,
        Tilde,
        PlusPlus,
        MinusMinus,
    )
}

impl From<UnaryPrefixOperatorWithIncrement> for IncrementOperator {
    fn from(value: UnaryPrefixOperatorWithIncrement) -> Self {
        match value {
            UnaryPrefixOperatorWithIncrement::Minus
            | UnaryPrefixOperatorWithIncrement::Bang
            | UnaryPrefixOperatorWithIncrement::Plus
            | UnaryPrefixOperatorWithIncrement::Tilde => unreachable!(),
            UnaryPrefixOperatorWithIncrement::PlusPlus => IncrementOperator::PlusPlus,
            UnaryPrefixOperatorWithIncrement::MinusMinus => IncrementOperator::MinusMinus,
        }
    }
}

impl From<UnaryPrefixOperatorWithIncrement> for UnaryPrefixOperator {
    fn from(value: UnaryPrefixOperatorWithIncrement) -> Self {
        match value {
            UnaryPrefixOperatorWithIncrement::Minus => UnaryPrefixOperator::Minus,
            UnaryPrefixOperatorWithIncrement::Bang => UnaryPrefixOperator::Bang,
            UnaryPrefixOperatorWithIncrement::Plus => UnaryPrefixOperator::Plus,
            UnaryPrefixOperatorWithIncrement::Tilde => UnaryPrefixOperator::Tilde,
            UnaryPrefixOperatorWithIncrement::PlusPlus
            | UnaryPrefixOperatorWithIncrement::MinusMinus => unreachable!(),
        }
    }
}

make_operator! {
    UnaryPostfixOperator,
    ErrorKind::ExpectedUnaryOperator,
    (
        // The weird operators of increment/decrement.
        // These will be immediately translated into
        // `Atom::Increment` or `Atom::Decrement` respectively,
        // after checking that their lhs is assignable (for example
        // `x++` is fine, but `5++` clearly isn't.
        PlusPlus,
        MinusMinus,
        // The even weirder "operators" of array access and
        // function calls. They will be immediately translated
        // into `Atom::ArrayAccess` and `Atom::FnCall` respectively,
        // but parsing them via the pratt parser allows writing expressions like
        // [1, 2, 3][0] or fn_array[5](a, b, c).
        LeftBracket,
        LeftParen,
    )
}

make_operator! {
    IncrementOperator,
    ErrorKind::ExpectedUnaryOperator, // irrelevant
    (
        PlusPlus,
        MinusMinus,
    )
}

make_operator! {
    AssignmentOperator,
    ErrorKind::ExpectedAssignmentOperator,
    (
        Equal,
        MinusEqual,
        PlusEqual,
        SlashEqual,
        StarEqual,
        PercentEqual,
        LessLessEqual,
        GreaterGreaterEqual,
        GreaterGreaterGreaterEqual,
    )
}

make_operator! {
    BinaryOperator,
    ErrorKind::ExpectedBinaryOperator,
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
        GreaterGreaterGreater,
        GreaterLess,
        GreaterEqual,
        Less,
        LessLess,
        LessEqual,
        GreaterBangLess,
        Ampersand,
        AmpersandAmpersand,
        Caret,
        Pipe,
        PipePipe,
        StarStar,
    )
}

#[derive(Debug, Clone)]
pub enum BinaryOrAssignmentOperator {
    Binary(BinaryOperator),
    Assignment(AssignmentOperator),
}

impl BinaryOrAssignmentOperator {
    pub fn binding_power(&self) -> (usize, usize) {
        match self {
            Self::Binary(binary_operator) => binary_operator.binding_power(),
            Self::Assignment(assignment_operator) => assignment_operator.binding_power(),
        }
    }
}

impl FromPeek for BinaryOrAssignmentOperator {
    fn from_peek(p: &impl Peek) -> Option<Self> {
        BinaryOperator::from_peek(p)
            .map(Self::Binary)
            .or_else(|| AssignmentOperator::from_peek(p).map(Self::Assignment))
    }
}

// The binding power of the `X` operator,
// which we define as maximal
pub fn x_binding_power() -> usize {
    25
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

impl AssignmentOperator {
    pub fn binding_power(&self) -> (usize, usize) {
        (2, 3)
    }
}

impl UnaryPrefixOperatorWithIncrement {
    pub fn right_binding_power(&self) -> usize {
        use UnaryPrefixOperatorWithIncrement::*;
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
            LeftBracket => 25,
            LeftParen => 27,
        }
    }
}

macro_rules! make_delimiter {
    ($ty: ident, $start: ident, $end: ident) => {
        #[derive(Clone, Debug, Default)]
        pub struct $ty;

        impl super::parser::Delimiter for $ty {
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

pub trait Spanned {
    fn span(&self) -> Span;
}

// // Just to make things work for now
// macro_rules! impl_dumb_temporary_span_info {
//     ($ty: ty) => {
//         impl Spanned for $ty {
//             fn span(&self) -> crate::nasl::error::Span {
//                 crate::nasl::syntax::Token::sentinel().span()
//             }
//         }
//     };
// }

// impl_dumb_temporary_span_info!(Ident);
