use std::vec;

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
pub struct VariableDecl;

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
    ExprStmt(ExprStmt),
}

#[derive(Clone, Debug)]
pub struct ExprStmt {
    pub expr: Expr,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Expr,
}
