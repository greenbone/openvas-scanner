use std::collections::HashMap;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::{Span, Spanned},
    syntax::grammar::{Ast, Statement},
};

use crate::linter::LintMsg;

const RULE: &str = "duplicate_function_declaration";

struct Declarations {
    name: String,
    spans: Vec<Span>,
}

impl Declarations {
    fn into_diagnostic(self) -> Diagnostic<()> {
        let message = format!("Function declared multiple times: {}", self.name);
        let labels = self
            .spans
            .into_iter()
            .enumerate()
            .map(|(index, span)| {
                if index == 0 {
                    Label::primary((), span).with_message("first declaration")
                } else {
                    Label::secondary((), span).with_message("redeclared here")
                }
            })
            .collect();
        Diagnostic::error()
            .with_message(message)
            .with_labels(labels)
    }
}

pub fn duplicate_function_declarations(ast: &Ast) -> Vec<LintMsg> {
    let mut declarations = Vec::<Declarations>::new();
    let mut indices = HashMap::<String, usize>::new();

    for declaration in ast.iter_stmts().filter_map(|statement| match statement {
        Statement::FnDecl(declaration) => Some(declaration),
        _ => None,
    }) {
        let name = declaration.fn_name.to_string();
        if let Some(index) = indices.get(&name) {
            declarations[*index].spans.push(declaration.fn_name.span());
        } else {
            indices.insert(name.clone(), declarations.len());
            declarations.push(Declarations {
                name,
                spans: vec![declaration.fn_name.span()],
            });
        }
    }

    declarations
        .into_iter()
        .filter(|declarations| declarations.spans.len() > 1)
        .map(|declarations| {
            let span = declarations.spans[0];
            let diagnostic = declarations.into_diagnostic();
            LintMsg::new(RULE, span, diagnostic)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::linter_test;

    linter_test!(duplicate_function, "function foo() {} function foo() {}");
    linter_test!(distinct_functions, "function foo() {} function bar() {}");
}
