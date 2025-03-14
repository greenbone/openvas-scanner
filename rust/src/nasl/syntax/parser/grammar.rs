use std::vec;

use crate::nasl::syntax::{
    token::{self, Literal},
    Token,
};

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
    pub operator: Token,
    pub right: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct Binary {
    pub left: Box<Expr>,
    pub operator: Token,
    pub right: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct Ident {
    pub ident: token::Ident,
}
