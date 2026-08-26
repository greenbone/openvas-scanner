use std::{collections::HashSet, mem};

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    SourceFile,
    error::Spanned,
    syntax::{
        Ident, Visitor,
        grammar::{Assignment, Atom, FnDecl, ForEach, Include, Increment, VarScope, VarScopeDecl},
        walk_ast, walk_block,
    },
};

use crate::linter::{
    LintMsg,
    ctx::{Cache, LintCtx},
};

const RULE: &str = "undeclared_variable";

struct Scope {
    globals: HashSet<String>,
    locals: HashSet<String>,
}

impl Scope {
    fn declare_global(&mut self, ident: &Ident) {
        self.globals.insert(ident.to_string());
    }

    fn declare_local(&mut self, ident: &Ident) {
        self.locals.insert(ident.to_string());
    }

    fn contains(&self, ident: &Ident) -> bool {
        let name = ident.to_string();
        self.locals.contains(&name) || self.globals.contains(&name)
    }
}

#[derive(Clone, Copy)]
enum ScopeKind {
    File,
    Function,
}

struct OrderedVariables<'cache> {
    cache: &'cache Cache,
    scope: Scope,
    scope_kind: ScopeKind,
    file: SourceFile,
    loaded: HashSet<String>,
    messages: Vec<LintMsg>,
}

impl<'cache> OrderedVariables<'cache> {
    fn new(
        cache: &'cache Cache,
        file: SourceFile,
        globals: HashSet<String>,
        scope_kind: ScopeKind,
    ) -> Self {
        let loaded = HashSet::from([file.name().clone()]);
        Self {
            cache,
            scope: Scope {
                globals,
                locals: HashSet::new(),
            },
            scope_kind,
            file,
            loaded,
            messages: vec![],
        }
    }

    fn declare_explicit(&mut self, declaration: &VarScopeDecl) {
        for ident in &declaration.idents {
            match (self.scope_kind, &declaration.scope) {
                (ScopeKind::File, _) | (ScopeKind::Function, VarScope::Global) => {
                    self.scope.declare_global(ident);
                }
                (ScopeKind::Function, VarScope::Local) => self.scope.declare_local(ident),
            }
        }
    }

    fn declare_implicit(&mut self, ident: &Ident) {
        match self.scope_kind {
            ScopeKind::File => self.scope.declare_global(ident),
            ScopeKind::Function if !self.scope.contains(ident) => self.scope.declare_local(ident),
            ScopeKind::Function => {}
        }
    }

    fn declare_iterator(&mut self, ident: &Ident) {
        match self.scope_kind {
            ScopeKind::File => self.scope.declare_global(ident),
            // Welcome to NASL where iterator vars still exist after loops
            ScopeKind::Function => self.scope.declare_local(ident),
        }
    }

    fn check_use(&mut self, ident: &Ident) {
        if self.scope.contains(ident) {
            return;
        }

        let name = ident.to_string();
        let message = format!("Variable `{name}` is not declared");
        let span = ident.span();
        let diagnostic = Diagnostic::error().with_message(&message).with_labels(vec![
            Label::primary((), span).with_message("undeclared variable"),
        ]);
        self.messages
            .push(LintMsg::new(RULE, self.file.clone(), span, diagnostic));
    }

    fn check_function(&mut self, declaration: &FnDecl) {
        let mut function = OrderedVariables::new(
            self.cache,
            self.file.clone(),
            self.scope.globals.clone(),
            ScopeKind::Function,
        );
        for argument in &declaration.args.items {
            function.scope.declare_local(argument);
        }
        walk_block(&mut function, &declaration.block);

        self.scope.globals = function.scope.globals;
        self.messages.append(&mut function.messages);
    }

    fn check_include(&mut self, include: &Include) {
        let Some((path, ast, file)) = self
            .cache
            .included_file(self.file.name(), &include.path)
            .map(|(path, cached)| (path.to_owned(), cached.ast().clone(), cached.file().clone()))
        else {
            return;
        };
        if !self.loaded.insert(path) {
            return;
        }

        let outer_file = mem::replace(&mut self.file, file);
        walk_ast(self, &ast);
        self.file = outer_file;
    }
}

impl<'ast> Visitor<'ast> for OrderedVariables<'_> {
    fn visit_var_scope_decl(&mut self, declaration: &'ast VarScopeDecl) {
        self.declare_explicit(declaration);
    }

    fn visit_fn_decl(&mut self, declaration: &'ast FnDecl) {
        self.check_function(declaration);
    }

    fn visit_include(&mut self, include: &'ast Include) {
        self.check_include(include);
    }

    fn visit_atom(&mut self, atom: &'ast Atom) {
        if let Atom::Ident(ident) = atom {
            self.check_use(ident);
        }
    }

    fn leave_assignment(&mut self, assignment: &'ast Assignment) {
        self.declare_implicit(&assignment.lhs.ident);
    }

    fn leave_increment(&mut self, increment: &'ast Increment) {
        self.declare_implicit(&increment.expr.ident);
    }

    fn visit_for_each_binding(&mut self, for_each: &'ast ForEach) {
        self.declare_iterator(&for_each.var);
    }

    fn should_walk_fn_body(&self, _declaration: &'ast FnDecl) -> bool {
        false
    }
}

pub fn undeclared_variables(ctx: &LintCtx) -> Vec<LintMsg> {
    let cache = &*ctx.cache;
    let globals = cache.predefined_vars().map(str::to_owned).collect();
    let mut variables = OrderedVariables::new(cache, ctx.file.clone(), globals, ScopeKind::File);
    walk_ast(&mut variables, ctx.ast);
    variables.messages
}

#[cfg(test)]
mod tests {
    use crate::linter_test;

    linter_test!(undeclared_variable, "display(missing);");
    linter_test!(assignment_declares_variable, "value = 1; display(value);");
    linter_test!(use_before_assignment, "display(value); value = 1;");
    linter_test!(assignment_rhs_is_read, "value = missing;");
    linter_test!(
        assignment_array_index_is_read,
        "array[index] = 1; display(array);"
    );
    linter_test!(
        function_scope,
        "function foo(arg) { local_var value; value = arg; display(value); display(missing); }"
    );
    linter_test!(
        function_local_does_not_leak,
        "function foo() { local_var scoped; } display(scoped);"
    );
    linter_test!(
        function_assignment_does_not_leak,
        "function foo() { scoped = 1; } display(scoped);"
    );
    linter_test!(
        function_use_before_assignment,
        "function foo() { display(scoped); scoped = 1; }"
    );
    linter_test!(
        function_global_is_visible_elsewhere,
        "function define() { global_var shared; } function use() { display(shared); } display(shared);"
    );
    linter_test!(
        top_level_local_is_global,
        "local_var shared; function use() { display(shared); }"
    );
    linter_test!(
        foreach_declares_iterator,
        "items = [1]; foreach item(items) { display(item); }"
    );
    linter_test!(
        predefined_variables,
        "if (description) { display(ACT_UNKNOWN, NASL_ERR_NOERR); }"
    );
    linter_test!(
        c_predefined_constants,
        "display(IPPROTO_ICMPV6, MSG_OOB, NOERR, ETIMEDOUT, ECONNRESET, EUNREACH, EUNKNOWN);"
    );
}
