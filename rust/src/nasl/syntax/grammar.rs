use std::vec;

use super::Statement;

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

    pub fn next(&mut self) -> Option<Statement> {
        let stmt = self.stmts.get(self.position);
        self.position += 1;
        stmt.cloned()
    }
}
