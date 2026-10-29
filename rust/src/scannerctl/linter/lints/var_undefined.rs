use std::collections::HashSet;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::Spanned,
    syntax::{
        Ident, Visitor,
        grammar::{
            Ast, Atom, Expr, FnDecl, ForEach, PlaceExpr, Unary, UnaryPrefixOperatorKind, VarScope,
            VarScopeDecl,
        },
        walk_ast,
    },
};

use crate::linter::{
    LintMsgs,
    calls::{FunctionId, RootCalls},
};

#[derive(Default)]
struct Scope {
    defined: HashSet<String>,
    globals: HashSet<String>,
    implicit: HashSet<String>,
    reads: Vec<Ident>,
}

#[derive(Default)]
struct Variables {
    top_level: Scope,
    functions: Vec<Scope>,
    current: Vec<usize>,
}

impl Variables {
    fn new(ast: &Ast) -> Self {
        let mut variables = Self::default();
        walk_ast(&mut variables, ast);
        variables
    }

    fn scope(&mut self) -> &mut Scope {
        match self.current.last() {
            Some(&index) => &mut self.functions[index],
            None => &mut self.top_level,
        }
    }

    fn scopes<'a>(&'a self, root: &'a RootCalls, file: usize) -> impl Iterator<Item = &'a Scope> {
        std::iter::once(&self.top_level).chain(self.functions.iter().enumerate().filter_map(
            move |(function, scope)| {
                root.reachable
                    .contains(&FunctionId { file, function })
                    .then_some(scope)
            },
        ))
    }
}

impl<'ast> Visitor<'ast> for Variables {
    fn visit_fn_decl(&mut self, decl: &'ast FnDecl) {
        self.current.push(self.functions.len());
        self.functions.push(Scope {
            defined: decl.args.items.iter().map(ToString::to_string).collect(),
            ..Scope::default()
        });
    }

    fn leave_fn_decl(&mut self, _: &'ast FnDecl) {
        self.current.pop();
    }

    fn visit_var_scope_decl(&mut self, decl: &'ast VarScopeDecl) {
        let scope = self.scope();
        let names = match decl.scope {
            VarScope::Local => &mut scope.defined,
            VarScope::Global => &mut scope.globals,
        };
        names.extend(decl.idents.iter().map(ToString::to_string));
    }

    fn visit_for_each(&mut self, stmt: &'ast ForEach) {
        self.scope().defined.insert(stmt.var.to_string());
    }

    fn visit_place_expr(&mut self, place: &'ast PlaceExpr) {
        self.scope().implicit.insert(place.ident.to_string());
    }

    fn visit_unary(&mut self, unary: &'ast Unary) {
        if unary.op.kind != UnaryPrefixOperatorKind::Bang {
            return;
        }
        let mut expr = unary.rhs.as_ref();
        while let Expr::Atom(Atom::ArrayAccess(access)) = expr {
            expr = &access.lhs_expr;
        }
        // We really love this in particular: Check for a defined variable by
        // if (!foo) { ... }
        // The linter unfortunately needs to explicitly handle this
        if let Expr::Atom(Atom::Ident(ident)) = expr {
            self.scope().implicit.insert(ident.to_string());
        }
    }

    fn visit_atom(&mut self, atom: &'ast Atom) {
        if let Atom::Ident(ident) = atom {
            self.scope().reads.push(ident.clone());
        }
    }
}

pub fn var_undefined(root: &RootCalls) -> Vec<LintMsgs> {
    let variables: Vec<_> = root
        .files
        .iter()
        .map(|file| Variables::new(&file.ast))
        .collect();
    let mut globals = super::builtins::builtin_variables();
    for (file, variables) in variables.iter().enumerate() {
        globals.extend(variables.top_level.defined.iter().cloned());
        for scope in variables.scopes(root, file) {
            globals.extend(scope.globals.iter().cloned());
            globals.extend(scope.implicit.difference(&scope.defined).cloned());
        }
    }
    variables
        .iter()
        .enumerate()
        .map(|(file, variables)| {
            let msgs = variables
                .scopes(root, file)
                .flat_map(|scope| {
                    scope
                        .reads
                        .iter()
                        .filter(|ident| {
                            let name = ident.to_string();
                            !scope.defined.contains(&name) && !globals.contains(&name)
                        })
                        .map(|ident| {
                            Diagnostic::error()
                                .with_message(format!("Undeclared variable '{}'", ident))
                                .with_labels(vec![
                                    Label::primary((), ident.span())
                                        .with_message("undeclared variable"),
                                ])
                                .into()
                        })
                })
                .collect();
            LintMsgs {
                file: root.files[file].file.clone(),
                msgs,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{linter_test, linter_test_multi};
    use std::path::Path;

    linter_test!(
        parameters_and_locals,
        "function f(arg) { local_var local; display(arg, local); } f(arg:1);"
    );
    linter_test!(
        independent_scopes,
        "function f(arg) { local_var private; } function g() { display(arg, private); } f(); g();"
    );
    linter_test!(
        called_functions,
        "function unused() { display(ignored); } function called() { assigned = 1; display(assigned, missing, missing); } called();"
    );
    linter_test!(
        reads_and_writes,
        "value = missing; array[index] = value; foreach item (array) display(item); display(array[other]);"
    );
    linter_test!(
        builtin_variables,
        "if (description) display(SCRIPT_NAME, COMMAND_LINE, IPPROTO_TCP, OPENVAS_VERSION, ACT_UNKNOWN, NOERR, ETIMEDOUT);"
    );
    linter_test!(
        defined_variable_check_not_op,
        "if (!optional) display(optional); if (!array[index]) display(array); display(missing);"
    );
    linter_test!(
        foreach_function_scope,
        "function f() { foreach item ([1]) display(item); } f(); display(item); foreach outer ([1]) display(outer); display(outer);"
    );
    linter_test!(
        implicit_globals_and_explicit_locals,
        "function f(parameter) { local_var private; parameter = 1; private = 2; shared = 3; if (!optional) display(optional); } f(); display(shared, optional, parameter, private);"
    );
    linter_test_multi!(included_globals,
        files: {
            "root.nasl" => "include(\"shared.inc\"); initialize(); display(shared, explicit);",
            "shared.inc" => "shared = 1; function initialize() { global_var explicit; explicit = 2; }",
        },
    );
    linter_test_multi!(globals_are_root_specific,
        files: {
            "one.nasl" => "include(\"shared.inc\"); provided = 1; check();",
            "two.nasl" => "include(\"shared.inc\"); check();",
            "shared.inc" => "function check() { display(provided); }",
        },
    );
}
