use std::collections::HashMap;

use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    error::{Span, Spanned},
    syntax::grammar::{Ast, FnArg, FnCall},
};

use crate::linter::LintMsg;

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

pub fn get_duplicate_args(fn_call: &FnCall) -> Vec<LintMsg> {
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
        .map(|(name, entry)| entry.into_diagnostic(&name).into())
        .collect()
}

pub fn duplicate_function_args(ast: &Ast) -> Vec<LintMsg> {
    ast.iter_fn_calls().flat_map(get_duplicate_args).collect()
}
