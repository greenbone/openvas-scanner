use std::{marker::PhantomData, vec};

use super::parser::{Error, FromPeek, Parser, cursor::Peek, error::ErrorKind};
use crate::nasl::{
    error::{Span, Spanned},
    syntax::token::{Ident, Literal, TokenKind},
};

#[derive(Clone, Debug)]
pub struct Ast {
    stmts: Vec<Statement>,
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
        Self { stmts }
    }

    pub fn stmts(self) -> Vec<Statement> {
        self.stmts
    }

    pub(crate) fn get(&self, stmt_index: usize) -> Option<&Statement> {
        self.stmts.get(stmt_index)
    }
}

#[derive(Clone, Debug)]
pub struct CommaSeparated<Item, Delim: Default> {
    pub items: Vec<Item>,
    delimiter: PhantomData<Delim>,
    span: Span,
}

impl<Item, Delim: Default> CommaSeparated<Item, Delim> {
    pub fn new(items: Vec<Item>, span: Span) -> Self {
        Self {
            items,
            delimiter: PhantomData,
            span,
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
    ForEach(ForEach),
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
    pub negate: bool,
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
pub struct ForEach {
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
    pub span: Span,
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
    ($ty: ident, $ty_kind: ident, $err: expr, ($($pat: ident$(,)?),*)) => {
        #[derive(Copy, Debug, Clone, PartialEq)]
        pub enum $ty_kind {
            $(
                $pat,
            )*
        }

        #[derive(Copy, Debug, Clone, PartialEq)]
        pub struct $ty {
            pub span: Span,
            pub kind: $ty_kind,
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
                let span = p.token_span();
                match kind {
                    $(
                        TokenKind::$pat => Some(Self { kind: $ty_kind::$pat, span }),
                    )*
                    _ => None,
                }
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match &self.kind {
                    $(
                        $ty_kind::$pat => write!(f, "{}", TokenKind::$pat),
                    )*
                }
            }
        }

        impl crate::nasl::error::Spanned for $ty {
            fn span(&self) -> Span {
                self.span
            }
        }
    }
}

make_operator! {
    UnaryPrefixOperator,
    UnaryPrefixOperatorKind,
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
    UnaryPrefixOperatorWithIncrementKind,
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
        let kind = match value.kind {
            UnaryPrefixOperatorWithIncrementKind::Minus
            | UnaryPrefixOperatorWithIncrementKind::Bang
            | UnaryPrefixOperatorWithIncrementKind::Plus
            | UnaryPrefixOperatorWithIncrementKind::Tilde => unreachable!(),
            UnaryPrefixOperatorWithIncrementKind::PlusPlus => IncrementOperatorKind::PlusPlus,
            UnaryPrefixOperatorWithIncrementKind::MinusMinus => IncrementOperatorKind::MinusMinus,
        };
        IncrementOperator {
            kind,
            span: value.span,
        }
    }
}

impl From<UnaryPrefixOperatorWithIncrement> for UnaryPrefixOperator {
    fn from(value: UnaryPrefixOperatorWithIncrement) -> Self {
        let kind = match value.kind {
            UnaryPrefixOperatorWithIncrementKind::Minus => UnaryPrefixOperatorKind::Minus,
            UnaryPrefixOperatorWithIncrementKind::Bang => UnaryPrefixOperatorKind::Bang,
            UnaryPrefixOperatorWithIncrementKind::Plus => UnaryPrefixOperatorKind::Plus,
            UnaryPrefixOperatorWithIncrementKind::Tilde => UnaryPrefixOperatorKind::Tilde,
            UnaryPrefixOperatorWithIncrementKind::PlusPlus
            | UnaryPrefixOperatorWithIncrementKind::MinusMinus => unreachable!(),
        };
        UnaryPrefixOperator {
            kind,
            span: value.span,
        }
    }
}

make_operator! {
    UnaryPostfixOperator,
    UnaryPostfixOperatorKind,
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
    IncrementOperatorKind,
    ErrorKind::ExpectedUnaryOperator, // irrelevant
    (
        PlusPlus,
        MinusMinus,
    )
}

make_operator! {
    AssignmentOperator,
    AssignmentOperatorKind,
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
    BinaryOperatorKind,
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
    fn binding_power(&self) -> (usize, usize) {
        use BinaryOperatorKind::*;
        match self.kind {
            StarStar => (24, 25),
            Star | Slash | Percent => (22, 23),
            Plus | Minus => (20, 21),
            LessLess | GreaterGreater | GreaterGreaterGreater => (18, 19),
            Ampersand => (16, 17),
            Caret => (14, 15),
            Pipe => (12, 13),
            Less | LessEqual | Greater | GreaterEqual | EqualEqual | BangEqual | GreaterLess
            | GreaterBangLess | EqualTilde | BangTilde => (10, 11),
            AmpersandAmpersand => (6, 7),
            PipePipe => (4, 5),
        }
    }
}

impl AssignmentOperator {
    fn binding_power(&self) -> (usize, usize) {
        (9, 8)
    }
}

impl UnaryPrefixOperatorWithIncrement {
    pub fn right_binding_power(&self) -> usize {
        use UnaryPrefixOperatorWithIncrementKind::*;
        match self.kind {
            Plus | Minus | Tilde | Bang | PlusPlus | MinusMinus => 29,
        }
    }
}

impl UnaryPostfixOperator {
    pub fn left_binding_power(&self) -> usize {
        use UnaryPostfixOperatorKind::*;
        match self.kind {
            PlusPlus => 23,
            MinusMinus => 23,
            LeftBracket => 31,
            LeftParen => 33,
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

impl Spanned for Expr {
    fn span(&self) -> Span {
        match self {
            Expr::Atom(atom) => atom.span(),
            Expr::Binary(binary) => binary.span(),
            Expr::Unary(unary) => unary.span(),
            Expr::Assignment(assignment) => assignment.span(),
        }
    }
}

impl<Item, Delim: Default> Spanned for CommaSeparated<Item, Delim> {
    fn span(&self) -> Span {
        self.span
    }
}

impl Spanned for Atom {
    fn span(&self) -> Span {
        match self {
            Atom::Literal(literal) => literal.span(),
            Atom::Ident(ident) => ident.span(),
            Atom::Array(array) => array.items.span(),
            Atom::ArrayAccess(array_access) => array_access.span(),
            Atom::FnCall(fn_call) => fn_call.span(),
            Atom::Increment(increment) => increment.span(),
        }
    }
}

impl Spanned for Binary {
    fn span(&self) -> Span {
        self.lhs.span().join(self.rhs.span())
    }
}

impl Spanned for Unary {
    fn span(&self) -> Span {
        self.rhs.span().join(self.op.span())
    }
}

impl Spanned for Assignment {
    fn span(&self) -> Span {
        self.lhs.span().join(self.rhs.span())
    }
}

impl Spanned for PlaceExpr {
    fn span(&self) -> Span {
        let mut span = self.ident.span();
        for arr in self.array_accesses.iter() {
            span = span.join(arr.span());
        }
        span
    }
}

impl Spanned for Increment {
    fn span(&self) -> Span {
        self.expr.span().join(self.op.span())
    }
}

impl Spanned for ArrayAccess {
    fn span(&self) -> Span {
        self.index_expr.span().join(self.lhs_expr.span())
    }
}

impl Spanned for FnCall {
    fn span(&self) -> Span {
        let mut span = self.fn_name.span().join(self.args.span());
        if let Some(num_repeats) = &self.num_repeats {
            span = span.join(num_repeats.span());
        }
        span
    }
}
