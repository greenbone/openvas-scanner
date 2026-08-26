use std::collections::HashMap;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::{Span, Spanned},
    syntax::grammar::Statement,
};

use crate::linter::{LintMsg, ctx::LintCtx};

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

fn duplicate_function_declarations_in_file(ctx: &LintCtx) -> Vec<LintMsg> {
    let mut declarations = Vec::<Declarations>::new();
    let mut indices = HashMap::<String, usize>::new();

    for declaration in ctx
        .ast
        .iter_stmts()
        .filter_map(|statement| match statement {
            Statement::FnDecl(declaration) => Some(declaration),
            _ => None,
        })
    {
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
            LintMsg::new(RULE, ctx.file.clone(), span, diagnostic)
        })
        .collect()
}

fn duplicate_function_declarations_across_files(ctx: &LintCtx) -> Vec<LintMsg> {
    let mut first_declarations = HashMap::<String, String>::new();
    let mut messages = vec![];

    let mut files = ctx.cache.files().collect::<Vec<_>>();
    files.sort_by(|(left, _), (right, _)| left.cmp(right));

    for (path, file) in files {
        let mut functions = file.functions().collect::<Vec<_>>();
        functions.sort_by_key(|(_, declaration)| {
            let span: std::ops::Range<usize> = declaration.fn_name.span().into();
            span.start
        });

        for (name, declaration) in functions {
            if let Some(first_file) = first_declarations.get(name) {
                if first_file == path {
                    continue;
                }

                let message = format!("Function declared multiple times: {name}");
                let span = declaration.fn_name.span();
                let diagnostic = Diagnostic::error()
                    .with_message(message)
                    .with_labels(vec![
                        Label::primary((), span).with_message("redeclared here"),
                    ])
                    .with_notes(vec![format!("also declared in {first_file}")]);
                messages.push(LintMsg::new(RULE, file.file().clone(), span, diagnostic));
            } else {
                first_declarations.insert(name.to_owned(), path.to_owned());
            }
        }
    }

    messages
}

fn builtin_function_redefinitions(ctx: &LintCtx) -> Vec<LintMsg> {
    let mut files = ctx.cache.files().collect::<Vec<_>>();
    files.sort_by(|(left, _), (right, _)| left.cmp(right));

    files
        .into_iter()
        .flat_map(|(_, file)| {
            let mut functions = file
                .functions()
                .filter(|(name, _)| ctx.builtin_defined(name))
                .collect::<Vec<_>>();
            functions.sort_by_key(|(_, declaration)| {
                let span: std::ops::Range<usize> = declaration.fn_name.span().into();
                span.start
            });

            functions.into_iter().map(move |(name, declaration)| {
                let span = declaration.fn_name.span();
                let diagnostic = Diagnostic::error()
                    .with_message(format!("Cannot redefine built-in function: {name}"))
                    .with_labels(vec![
                        Label::primary((), span).with_message("built-in function redefined here"),
                    ]);
                LintMsg::new(RULE, file.file().clone(), span, diagnostic)
            })
        })
        .collect()
}

pub fn duplicate_function_declarations(ctx: &LintCtx) -> Vec<LintMsg> {
    duplicate_function_declarations_in_file(ctx)
        .into_iter()
        .chain(duplicate_function_declarations_across_files(ctx))
        .chain(builtin_function_redefinitions(ctx))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::linter_test;

    linter_test!(duplicate_function, "function foo() {} function foo() {}");
    linter_test!(distinct_functions, "function foo() {} function bar() {}");
    linter_test!(builtin_function, "function display() {}");
}
