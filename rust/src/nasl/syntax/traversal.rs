use super::{
    grammar::*,
    visitor::{Visitor, walk_ast},
};

struct ExprCollector<'a> {
    exprs: Vec<&'a Expr>,
}

impl<'a> ExprCollector<'a> {
    fn new() -> Self {
        Self { exprs: Vec::new() }
    }
}

impl<'a> Visitor<'a> for ExprCollector<'a> {
    fn visit_expr(&mut self, expr: &'a Expr) {
        self.exprs.push(expr);
    }
}

struct StmtCollector<'a> {
    stmts: Vec<&'a Statement>,
}

impl<'a> StmtCollector<'a> {
    fn new() -> Self {
        Self { stmts: Vec::new() }
    }
}

impl<'a> Visitor<'a> for StmtCollector<'a> {
    fn visit_statement(&mut self, stmt: &'a Statement) {
        self.stmts.push(stmt);
    }
}

pub struct ExprIterator<'a> {
    exprs: Vec<&'a Expr>,
    index: usize,
}

impl<'a> ExprIterator<'a> {
    pub fn new(ast: &'a Ast) -> Self {
        let mut collector = ExprCollector::new();
        walk_ast(&mut collector, ast);
        Self {
            exprs: collector.exprs,
            index: 0,
        }
    }
}

pub struct StmtIterator<'a> {
    stmts: Vec<&'a Statement>,
    index: usize,
}

impl<'a> StmtIterator<'a> {
    pub fn new(ast: &'a Ast) -> Self {
        let mut collector = StmtCollector::new();
        walk_ast(&mut collector, ast);
        Self {
            stmts: collector.stmts,
            index: 0,
        }
    }
}

impl<'a> Iterator for ExprIterator<'a> {
    type Item = &'a Expr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.exprs.len() {
            let expr = self.exprs[self.index];
            self.index += 1;
            Some(expr)
        } else {
            None
        }
    }
}

impl<'a> Iterator for StmtIterator<'a> {
    type Item = &'a Statement;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.stmts.len() {
            let stmt = self.stmts[self.index];
            self.index += 1;
            Some(stmt)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::Code;

    #[test]
    fn iter_exprs() {
        let ast = Code::from_string(
            r#"
function foo() {
    a += 1;
    b += 1;
}

if (a == 1) {
    a += 1;
}
else {
    b += 1;
}
            "#,
        )
        .parse()
        .emit_errors()
        .unwrap();

        let collected: Vec<_> = ast.iter_exprs().collect();
        insta::assert_debug_snapshot!(collected);
    }

    #[test]
    fn iter_stmts() {
        let ast = Code::from_string(
            r#"
function foo() {
    a += 1;
    b += 1;
}

if (a == 1) {
    a += 1;
}
else {
    b += 1;
}
            "#,
        )
        .parse()
        .emit_errors()
        .unwrap();

        let collected: Vec<_> = ast.iter_stmts().collect();
        insta::assert_debug_snapshot!(collected);
    }
}
