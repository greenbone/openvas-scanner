use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::syntax::{
    Visitor,
    grammar::{Ast, Atom, Expr, FnCall, If},
    walk_ast,
};

use crate::linter::LintMsg;

pub fn comma_spacing(ast: &Ast) -> Vec<LintMsg> {
    let mut checker = XrefSpacing::default();
    walk_ast(&mut checker, ast);
    checker.msgs
}

#[derive(Default)]
struct XrefSpacing {
    description: Vec<bool>,
    xref: Vec<bool>,
    msgs: Vec<LintMsg>,
}

impl<'ast> Visitor<'ast> for XrefSpacing {
    fn visit_if(&mut self, stmt: &'ast If) {
        let is_description = self.description.last().copied().unwrap_or(false)
            || stmt.if_branches.iter().any(|(condition, _)| {
                matches!(condition, Expr::Atom(Atom::Ident(ident)) if ident.to_string() == "description")
            });
        self.description.push(is_description);
    }

    fn leave_if(&mut self, _: &'ast If) {
        self.description.pop();
    }

    fn visit_fn_call(&mut self, call: &'ast FnCall) {
        self.xref.push(
            self.xref.last().copied().unwrap_or(false) || call.fn_name.to_string() == "script_xref",
        );
    }

    fn leave_fn_call(&mut self, _: &'ast FnCall) {
        self.xref.pop();
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if self.description.last() != Some(&true) || self.xref.last() != Some(&true) {
            return;
        }
        if let Expr::Atom(Atom::Literal(literal)) = expr
            && literal.as_str().is_some_and(|value| value.contains(", "))
        {
            self.msgs.push(
                Diagnostic::error()
                    .with_message("Spaces after commas are not allowed in script_xref strings")
                    .with_labels(vec![
                        Label::primary((), literal.span)
                            .with_message("remove the space after the comma"),
                    ])
                    .into(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::linter_test;

    linter_test!(
        bad_spacing,
        "if (description) { script_xref(name:\"A, B\", value:\"1, 2\", csv:\"3, 4\"); }"
    );
    linter_test!(
        nested_expressions,
        "if (description) { if (TRUE) { script_xref(name:\"URL\", value:strcat(\"a, b\", \"c\")); } script_xref(name:\"URL\", value:\"x, y\"); }"
    );
    linter_test!(
        other_strings_are_ignored,
        "if (description) { script_xref(name:\"URL\", csv:\"a,b\"); display(\"a, b\"); if (TRUE) { display(\"a, b\"); } } script_xref(name:\"URL\", value:\"a, b\");"
    );
}
