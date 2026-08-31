use codespan_reporting::diagnostic::{Diagnostic, Label};
use scannerlib::nasl::{
    SourceFile,
    error::{Span, Spanned},
    syntax::{
        Visitor,
        grammar::{Atom, FnArg, FnCall},
        walk_ast,
    },
};

use crate::linter::{LintMsg, ctx::LintCtx};

const RULE: &str = "script_xref";

struct Call {
    span: Span,
    missing_name: bool,
    missing_reference: bool,
    invalid_string_spans: Vec<Span>,
}

impl Call {
    fn new(call: &FnCall) -> Self {
        let mut has_name = false;
        let mut has_value = false;
        let mut has_csv = false;

        for argument in &call.args.items {
            let FnArg::Named(argument) = argument else {
                continue;
            };
            match argument.ident.to_string().as_str() {
                "name" => has_name = true,
                "value" => has_value = true,
                "csv" => has_csv = true,
                _ => {}
            }
        }

        Self {
            span: call.fn_name.span(),
            missing_name: !has_name,
            missing_reference: !has_value && !has_csv,
            invalid_string_spans: vec![],
        }
    }

    fn is_valid(&self) -> bool {
        !self.missing_name && !self.missing_reference && self.invalid_string_spans.is_empty()
    }

    fn into_message(self, file: SourceFile) -> Option<LintMsg> {
        if self.is_valid() {
            return None;
        }

        let mut labels = vec![];
        let missing_message = match (self.missing_name, self.missing_reference) {
            (true, true) => Some("`name` and at least one of `value` or `csv` are required"),
            (true, false) => Some("`name` is required"),
            (false, true) => Some("at least one of `value` or `csv` is required"),
            (false, false) => None,
        };
        if let Some(message) = missing_message {
            labels.push(Label::primary((), self.span).with_message(message));
        }
        labels.extend(self.invalid_string_spans.into_iter().map(|span| {
            Label::primary((), span).with_message("xref strings must not contain `, `")
        }));

        let diagnostic = Diagnostic::error()
            .with_message("Invalid script_xref call")
            .with_labels(labels);
        Some(LintMsg::new(RULE, file, self.span, diagnostic))
    }
}

#[derive(Default)]
struct ScriptXrefVisitor {
    active_calls: Vec<Call>,
    calls: Vec<Call>,
}

impl<'ast> Visitor<'ast> for ScriptXrefVisitor {
    fn visit_fn_call(&mut self, call: &'ast FnCall) {
        if call.fn_name.to_string() == "script_xref" {
            self.active_calls.push(Call::new(call));
        }
    }

    fn leave_fn_call(&mut self, call: &'ast FnCall) {
        if call.fn_name.to_string() == "script_xref" {
            self.calls.push(self.active_calls.pop().unwrap());
        }
    }

    fn visit_atom(&mut self, atom: &'ast Atom) {
        if atom
            .as_string_literal()
            .is_some_and(|value| value.contains(", "))
            && let Some(call) = self.active_calls.last_mut()
        {
            call.invalid_string_spans.push(atom.span());
        }
    }
}

pub fn script_xref(ctx: &LintCtx) -> Vec<LintMsg> {
    let mut files = ctx.cache.files().collect::<Vec<_>>();
    files.sort_by(|(left, _), (right, _)| left.cmp(right));

    files
        .into_iter()
        .flat_map(|(_, file)| {
            let mut visitor = ScriptXrefVisitor::default();
            walk_ast(&mut visitor, file.ast());
            visitor
                .calls
                .into_iter()
                .filter_map(|call| call.into_message(file.file().clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{linter_test, linter_test_multi};

    linter_test!(
        valid_script_xrefs,
        r#"
script_xref(name: "URL", value: "https://example.com");
script_xref(name: "CVE", csv: "CVE-2025-0001,CVE-2025-0002");
script_xref(name: "GHSA", value: "GHSA-3333-4444-5555", csv: "GHSA-1111-2222-3333,GHSA-2222-3333-4444");
"#
    );

    linter_test!(
        malformed_script_xrefs,
        r#"
script_xref(value: "https://example.com");
script_xref(name: "URL");
script_xref();
script_xref(name: "URL", value: "https://example.com/a, b");
script_xref(name: "CVE, GHSA", csv: "CVE-2025-0001, CVE-2025-0002");
"#
    );

    linter_test_multi!(
        malformed_script_xref_in_shared_include_is_emitted_once,
        roots: ["a.nasl", "b.nasl"],
        files: {
            "a.nasl" => "include(\"xref.inc\");",
            "b.nasl" => "include(\"xref.inc\");",
            "xref.inc" => "script_xref(name: \"URL\");",
        },
    );
}
