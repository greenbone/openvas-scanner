use super::grammar::*;

pub trait Visitor<'ast> {
    fn visit_ast(&mut self, _ast: &'ast Ast) {}

    // Statement visitors
    fn visit_statement(&mut self, _stmt: &'ast Statement) {}
    fn visit_var_scope_decl(&mut self, _decl: &'ast VarScopeDecl) {}
    fn visit_fn_decl(&mut self, _decl: &'ast FnDecl) {}
    fn visit_block(&mut self, _block: &'ast Block<Statement>) {}
    fn visit_while(&mut self, _while_stmt: &'ast While) {}
    fn visit_repeat(&mut self, _repeat: &'ast Repeat) {}
    fn visit_for_each(&mut self, _for_each: &'ast ForEach) {}
    fn visit_for(&mut self, _for_stmt: &'ast For) {}
    fn visit_if(&mut self, _if_stmt: &'ast If) {}
    fn visit_include(&mut self, _include: &'ast Include) {}
    fn visit_exit(&mut self, _exit: &'ast Exit) {}
    fn visit_return(&mut self, _return_stmt: &'ast Return) {}

    // Expression visitors
    fn visit_expr(&mut self, _expr: &'ast Expr) {}
    fn visit_binary(&mut self, _binary: &'ast Binary) {}
    fn visit_unary(&mut self, _unary: &'ast Unary) {}
    fn visit_assignment(&mut self, _assignment: &'ast Assignment) {}

    // Atom visitors
    fn visit_atom(&mut self, _atom: &'ast Atom) {}
    fn visit_array(&mut self, _array: &'ast Array) {}
    fn visit_array_access(&mut self, _access: &'ast ArrayAccess) {}
    fn visit_fn_call(&mut self, _call: &'ast FnCall) {}
    fn visit_increment(&mut self, _inc: &'ast Increment) {}
    fn visit_literal(&mut self, _literal: &'ast super::super::syntax::token::Literal) {}
    fn visit_ident(&mut self, _ident: &'ast super::super::syntax::token::Ident) {}

    // Additional visitors for function arguments and place expressions
    fn visit_fn_arg(&mut self, _arg: &'ast FnArg) {}
    fn visit_place_expr(&mut self, _place: &'ast PlaceExpr) {}
}

pub fn walk_ast<'ast, V: Visitor<'ast>>(visitor: &mut V, ast: &'ast Ast) {
    visitor.visit_ast(ast);
    for stmt in ast.iter_root_stmts() {
        walk_statement(visitor, stmt);
    }
}

fn walk_statement<'ast, V: Visitor<'ast>>(visitor: &mut V, stmt: &'ast Statement) {
    visitor.visit_statement(stmt);
    match stmt {
        Statement::ExprStmt(expr) => walk_expr(visitor, expr),
        Statement::Block(block) => walk_block(visitor, block),
        Statement::While(while_stmt) => walk_while(visitor, while_stmt),
        Statement::Repeat(repeat) => walk_repeat(visitor, repeat),
        Statement::ForEach(for_each) => walk_for_each(visitor, for_each),
        Statement::For(for_stmt) => walk_for(visitor, for_stmt),
        Statement::If(if_stmt) => walk_if(visitor, if_stmt),
        Statement::Return(return_stmt) => walk_return(visitor, return_stmt),
        Statement::Exit(exit) => walk_exit(visitor, exit),
        Statement::FnDecl(fn_decl) => walk_fn_decl(visitor, fn_decl),
        Statement::VarScopeDecl(var_decl) => walk_var_scope_decl(visitor, var_decl),
        Statement::Include(include) => walk_include(visitor, include),
        Statement::Break | Statement::Continue | Statement::NoOp => {}
    }
}

fn walk_block<'ast, V: Visitor<'ast>>(visitor: &mut V, block: &'ast Block<Statement>) {
    visitor.visit_block(block);
    for stmt in &block.items {
        walk_statement(visitor, stmt);
    }
}

fn walk_while<'ast, V: Visitor<'ast>>(visitor: &mut V, while_stmt: &'ast While) {
    visitor.visit_while(while_stmt);
    walk_expr(visitor, &while_stmt.condition);
    walk_block(visitor, &while_stmt.block);
}

fn walk_repeat<'ast, V: Visitor<'ast>>(visitor: &mut V, repeat: &'ast Repeat) {
    visitor.visit_repeat(repeat);
    walk_block(visitor, &repeat.block);
    walk_expr(visitor, &repeat.condition);
}

fn walk_for_each<'ast, V: Visitor<'ast>>(visitor: &mut V, for_each: &'ast ForEach) {
    visitor.visit_for_each(for_each);
    visitor.visit_ident(&for_each.var);
    walk_expr(visitor, &for_each.array);
    walk_block(visitor, &for_each.block);
}

fn walk_for<'ast, V: Visitor<'ast>>(visitor: &mut V, for_stmt: &'ast For) {
    visitor.visit_for(for_stmt);
    if let Some(init) = &for_stmt.initializer {
        walk_statement(visitor, init);
    }
    walk_expr(visitor, &for_stmt.condition);
    if let Some(inc) = &for_stmt.increment {
        walk_statement(visitor, inc);
    }
    walk_block(visitor, &for_stmt.block);
}

fn walk_if<'ast, V: Visitor<'ast>>(visitor: &mut V, if_stmt: &'ast If) {
    visitor.visit_if(if_stmt);
    for (condition, block) in &if_stmt.if_branches {
        walk_expr(visitor, condition);
        walk_block(visitor, block);
    }
    if let Some(else_block) = &if_stmt.else_branch {
        walk_block(visitor, else_block);
    }
}

fn walk_return<'ast, V: Visitor<'ast>>(visitor: &mut V, return_stmt: &'ast Return) {
    visitor.visit_return(return_stmt);
    if let Some(expr) = &return_stmt.expr {
        walk_expr(visitor, expr);
    }
}

fn walk_exit<'ast, V: Visitor<'ast>>(visitor: &mut V, exit: &'ast Exit) {
    visitor.visit_exit(exit);
    walk_expr(visitor, &exit.expr);
}

fn walk_fn_decl<'ast, V: Visitor<'ast>>(visitor: &mut V, fn_decl: &'ast FnDecl) {
    visitor.visit_fn_decl(fn_decl);
    visitor.visit_ident(&fn_decl.fn_name);
    for arg in &fn_decl.args.items {
        visitor.visit_ident(arg);
    }
    walk_block(visitor, &fn_decl.block);
}

fn walk_var_scope_decl<'ast, V: Visitor<'ast>>(visitor: &mut V, var_decl: &'ast VarScopeDecl) {
    visitor.visit_var_scope_decl(var_decl);
    for ident in &var_decl.idents {
        visitor.visit_ident(ident);
    }
}

fn walk_include<'ast, V: Visitor<'ast>>(visitor: &mut V, include: &'ast Include) {
    visitor.visit_include(include);
}

fn walk_expr<'ast, V: Visitor<'ast>>(visitor: &mut V, expr: &'ast Expr) {
    visitor.visit_expr(expr);
    match expr {
        Expr::Binary(binary) => walk_binary(visitor, binary),
        Expr::Unary(unary) => walk_unary(visitor, unary),
        Expr::Assignment(assignment) => walk_assignment(visitor, assignment),
        Expr::Atom(atom) => walk_atom(visitor, atom),
    }
}

fn walk_binary<'ast, V: Visitor<'ast>>(visitor: &mut V, binary: &'ast Binary) {
    visitor.visit_binary(binary);
    walk_expr(visitor, &binary.lhs);
    walk_expr(visitor, &binary.rhs);
}

fn walk_unary<'ast, V: Visitor<'ast>>(visitor: &mut V, unary: &'ast Unary) {
    visitor.visit_unary(unary);
    walk_expr(visitor, &unary.rhs);
}

fn walk_assignment<'ast, V: Visitor<'ast>>(visitor: &mut V, assignment: &'ast Assignment) {
    visitor.visit_assignment(assignment);
    walk_place_expr(visitor, &assignment.lhs);
    walk_expr(visitor, &assignment.rhs);
}

fn walk_place_expr<'ast, V: Visitor<'ast>>(visitor: &mut V, place: &'ast PlaceExpr) {
    visitor.visit_place_expr(place);
    visitor.visit_ident(&place.ident);
    for access in &place.array_accesses {
        walk_expr(visitor, access);
    }
}

fn walk_atom<'ast, V: Visitor<'ast>>(visitor: &mut V, atom: &'ast Atom) {
    visitor.visit_atom(atom);
    match atom {
        Atom::Literal(literal) => visitor.visit_literal(literal),
        Atom::Ident(ident) => visitor.visit_ident(ident),
        Atom::Array(array) => walk_array(visitor, array),
        Atom::ArrayAccess(access) => walk_array_access(visitor, access),
        Atom::FnCall(call) => walk_fn_call(visitor, call),
        Atom::Increment(inc) => walk_increment(visitor, inc),
    }
}

fn walk_array<'ast, V: Visitor<'ast>>(visitor: &mut V, array: &'ast Array) {
    visitor.visit_array(array);
    for item in &array.items.items {
        walk_expr(visitor, item);
    }
}

fn walk_array_access<'ast, V: Visitor<'ast>>(visitor: &mut V, access: &'ast ArrayAccess) {
    visitor.visit_array_access(access);
    walk_expr(visitor, &access.index_expr);
    walk_expr(visitor, &access.lhs_expr);
}

fn walk_fn_call<'ast, V: Visitor<'ast>>(visitor: &mut V, call: &'ast FnCall) {
    visitor.visit_fn_call(call);
    visitor.visit_ident(&call.fn_name);
    if let Some(repeats) = &call.num_repeats {
        walk_expr(visitor, repeats);
    }
    for arg in &call.args.items {
        walk_fn_arg(visitor, arg);
    }
}

fn walk_fn_arg<'ast, V: Visitor<'ast>>(visitor: &mut V, arg: &'ast FnArg) {
    visitor.visit_fn_arg(arg);
    match arg {
        FnArg::Anonymous(anon) => walk_expr(visitor, &anon.expr),
        FnArg::Named(named) => {
            visitor.visit_ident(&named.ident);
            walk_expr(visitor, &named.expr);
        }
    }
}

fn walk_increment<'ast, V: Visitor<'ast>>(visitor: &mut V, inc: &'ast Increment) {
    visitor.visit_increment(inc);
    walk_place_expr(visitor, &inc.expr);
}
