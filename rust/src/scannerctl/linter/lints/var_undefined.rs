use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::Spanned,
    syntax::{
        Visitor,
        grammar::{
            Atom, BinaryOperatorKind, Expr, FnDecl, ForEach, Include, PlaceExpr, Unary,
            UnaryPrefixOperatorKind, VarScope, VarScopeDecl,
        },
        walk_ast,
    },
};

use crate::linter::{
    LintMsgs,
    calls::{FunctionId, RootCalls},
};

struct Variables<'a> {
    root: &'a RootCalls<'a>,
    files: HashMap<&'a Path, usize>,
    globals: HashSet<String>,
    locals: Vec<HashSet<String>>,
    active: Vec<bool>,
    visited: HashSet<usize>,
    file: usize,
    function: usize,
    include: usize,
    msgs: Vec<LintMsgs>,
}

impl Variables<'_> {
    fn active(&self) -> bool {
        self.active.last().copied().unwrap_or(true)
    }

    fn define(&mut self, name: String) {
        if self.active()
            && !self
                .locals
                .last()
                .is_some_and(|locals| locals.contains(&name))
        {
            self.globals.insert(name);
        }
    }

    fn check_file(&mut self, file: usize) {
        if !self.visited.insert(file) {
            return;
        }
        let previous = (self.file, self.function, self.include);
        self.file = file;
        self.function = 0;
        self.include = 0;
        walk_ast(self, &self.root.files[file].ast);
        (self.file, self.function, self.include) = previous;
    }
}

impl<'ast> Visitor<'ast> for Variables<'_> {
    fn visit_fn_decl(&mut self, decl: &'ast FnDecl) {
        let id = FunctionId {
            file: self.file,
            function: self.function,
        };
        self.function += 1;
        self.active
            .push(self.active() && self.root.reachable.contains(&id));
        self.locals
            .push(decl.args.items.iter().map(ToString::to_string).collect());
    }

    fn leave_fn_decl(&mut self, _: &'ast FnDecl) {
        self.active.pop();
        self.locals.pop();
    }

    fn visit_include(&mut self, _: &'ast Include) {
        let path = &self.root.files[self.file].includes[self.include];
        self.include += 1;
        if self.active() {
            self.check_file(self.files[path.as_path()]);
        }
    }

    fn visit_var_scope_decl(&mut self, decl: &'ast VarScopeDecl) {
        if !self.active() {
            return;
        }
        let names = match decl.scope {
            VarScope::Local => self.locals.last_mut().unwrap_or(&mut self.globals),
            VarScope::Global => &mut self.globals,
        };
        names.extend(decl.idents.iter().map(ToString::to_string));
    }

    fn visit_for_each(&mut self, stmt: &'ast ForEach) {
        if self.active() {
            self.locals
                .last_mut()
                .unwrap_or(&mut self.globals)
                .insert(stmt.var.to_string());
        }
    }

    fn visit_place_expr(&mut self, place: &'ast PlaceExpr) {
        self.define(place.ident.to_string());
    }

    fn visit_unary(&mut self, unary: &'ast Unary) {
        if unary.op.kind != UnaryPrefixOperatorKind::Bang {
            return;
        }
        let mut expr = match unary.rhs.as_ref() {
            Expr::Binary(binary) if binary.op.kind == BinaryOperatorKind::EqualEqual => {
                match (binary.lhs.as_ref(), binary.rhs.as_ref()) {
                    (expr, Expr::Atom(Atom::Literal(literal))) if literal.is_null() => expr,
                    (Expr::Atom(Atom::Literal(literal)), expr) if literal.is_null() => expr,
                    _ => return,
                }
            }
            expr => expr,
        };
        while let Expr::Atom(Atom::ArrayAccess(access)) = expr {
            expr = &access.lhs_expr;
        }
        // We really love this in particular: Check for a defined variable by
        // if (!foo) { ... }
        // The linter unfortunately needs to explicitly handle this
        if let Expr::Atom(Atom::Ident(ident)) = expr {
            self.define(ident.to_string());
        }
    }

    fn visit_atom(&mut self, atom: &'ast Atom) {
        if !self.active() {
            return;
        }
        if let Atom::Ident(ident) = atom {
            let name = ident.to_string();
            if !self.globals.contains(&name)
                && !self
                    .locals
                    .last()
                    .is_some_and(|locals| locals.contains(&name))
            {
                self.msgs[self.file].msgs.push(
                    Diagnostic::error()
                        .with_message(format!("Undeclared variable '{}'", ident))
                        .with_labels(vec![
                            Label::primary((), ident.span()).with_message("undeclared variable"),
                        ])
                        .into(),
                );
            }
        }
    }
}

pub fn var_undefined(root: &RootCalls) -> Vec<LintMsgs> {
    let mut variables = Variables {
        root,
        files: root
            .files
            .iter()
            .enumerate()
            .map(|(index, file)| (Path::new(file.file.name()), index))
            .collect(),
        globals: super::builtins::builtin_variables(),
        locals: vec![],
        active: vec![],
        visited: HashSet::new(),
        file: 0,
        function: 0,
        include: 0,
        msgs: root
            .files
            .iter()
            .map(|file| LintMsgs {
                file: file.file.clone(),
                msgs: vec![],
            })
            .collect(),
    };
    variables.check_file(0);
    variables.msgs
}

#[cfg(test)]
mod tests {
    use crate::{linter_test, linter_test_multi};
    use std::path::Path;

    linter_test!(
        declaration_order,
        "display(value); value = 1; display(value); function f() { display(local); local_var local; display(local); display(optional); if (!optional) display(optional); } f();"
    );
    linter_test!(
        array_read_order,
        "display(array[array = 1]); display(array);"
    );
    linter_test_multi!(include_order,
        files: {
            "root.nasl" => "display(included); before = 1; include(\"nested/first.inc\"); display(included); after = 1;",
            "nested/first.inc" => "display(before); include(\"second.inc\"); display(after);",
            "nested/second.inc" => "included = 1;",
        },
    );
    linter_test!(
        function_definition_order,
        "function f() { display(later); } later = 1; f(); function g() { display(later); } g();"
    );
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
        defined_variable_check_not_op_expression,
        "if (!(optional == NULL)) display(optional); if (!(NULL == other)) display(other); if (!(array[0] == NULL)) display(array);"
    );
    linter_test!(
        other_negated_expressions,
        "if (!(first && second)) display(first); if (!(other == 1)) display(other); if (!0) display(later);"
    );
    linter_test!(
        defined_variable_check_not_op_call,
        "if (!isnull(missing)) display(missing);"
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
            "one.nasl" => "provided = 1; include(\"shared.inc\"); check();",
            "two.nasl" => "include(\"shared.inc\"); check();",
            "shared.inc" => "function check() { display(provided); }",
        },
    );
}
