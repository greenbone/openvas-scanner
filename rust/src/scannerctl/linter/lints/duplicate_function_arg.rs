use std::collections::HashMap;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    SourceFile,
    error::{Span, Spanned},
    syntax::grammar::{FnArg, FnCall},
};

use crate::linter::{LintMsg, ctx::LintCtx};

const RULE: &str = "duplicate_function_argument";

struct Entry {
    count: usize,
    spans: Vec<Span>,
}

impl Entry {
    fn into_diagnostic(self, name: &str) -> Diagnostic<()> {
        let msg = format!("Function argument passed multiple times: {}", name);
        let labels = self
            .spans
            .into_iter()
            .enumerate()
            .map(|(i, span)| {
                if i == 0 {
                    Label::primary((), span).with_message(msg.clone())
                } else {
                    Label::primary((), span).with_message("Also here")
                }
            })
            .collect();
        Diagnostic::warning()
            .with_message(msg.clone())
            .with_labels(labels)
    }
}

fn get_duplicate_args(file: &SourceFile, fn_call: &FnCall) -> Vec<LintMsg> {
    let mut counter: HashMap<_, _> = HashMap::default();
    for arg in fn_call.args.items.iter() {
        if let FnArg::Named(arg) = arg {
            let entry = counter.entry(arg.ident.to_string()).or_insert(Entry {
                count: 0,
                spans: vec![],
            });
            entry.count += 1;
            entry.spans.push(arg.ident.span());
        }
    }
    counter
        .into_iter()
        .filter(|(_, entry)| entry.count > 1)
        .map(|(name, entry)| {
            let span = entry.spans[0];
            let diagnostic = entry.into_diagnostic(&name);
            LintMsg::new(RULE, file.clone(), span, diagnostic)
        })
        .collect()
}

pub fn duplicate_function_args(ctx: &LintCtx) -> Vec<LintMsg> {
    let mut files = ctx.cache.files().collect::<Vec<_>>();
    files.sort_by(|(left, _), (right, _)| left.cmp(right));

    files
        .into_iter()
        .flat_map(|(_, file)| {
            file.ast()
                .iter_fn_calls()
                .flat_map(|fn_call| get_duplicate_args(file.file(), fn_call))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::linter_test;

    linter_test!(duplicate_arg, "foo(a: 1, a: 2);");
    linter_test!(duplicate_arg_triple, "foo(x: 1, y: 2, x: 3);");
    linter_test!(no_duplicate_args, "foo(a: 1, b: 2);");
}
