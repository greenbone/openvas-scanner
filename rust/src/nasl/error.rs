use std::ops::Range;

use codespan_reporting::diagnostic::Diagnostic;
use codespan_reporting::diagnostic::Label;
use codespan_reporting::term;
use codespan_reporting::term::termcolor::Buffer;
use codespan_reporting::term::termcolor::ColorChoice;
use codespan_reporting::term::termcolor::StandardStream;

use super::code::SourceFile;
use super::syntax::CharIndex;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Span {
    start: CharIndex,
    end: CharIndex,
}

impl Span {
    pub(crate) fn new(start: CharIndex, end: CharIndex) -> Self {
        assert!(start.0 <= end.0);
        Self { start, end }
    }

    pub(crate) fn start(&self) -> CharIndex {
        self.start
    }

    pub(crate) fn end(&self) -> CharIndex {
        self.end
    }

    pub(crate) fn join(&self, span: Span) -> Span {
        Span::new(
            CharIndex(self.start.0.min(span.start.0)),
            CharIndex(self.end.0.max(span.end.0)),
        )
    }
}

impl From<Span> for Range<usize> {
    fn from(value: Span) -> Range<usize> {
        value.start.0..value.end.0
    }
}

pub trait Spanned {
    fn span(&self) -> Span;
}

impl Spanned for Span {
    fn span(&self) -> Span {
        *self
    }
}

pub trait IntoDiagnostic {
    fn into_diagnostic(self) -> Diagnostic<()>;
}

pub fn basic_error_diagnostic(msg: String, span: Span) -> Diagnostic<()> {
    Diagnostic::error()
        .with_message(msg.clone())
        .with_labels(vec![Label::primary((), span).with_message(msg)])
}

pub fn emit_errors<T: IntoDiagnostic>(file: &SourceFile, errs: impl Iterator<Item = T>) {
    let writer = StandardStream::stderr(ColorChoice::Always);
    let config = codespan_reporting::term::Config::default();
    for err in errs {
        let diagnostic = err.into_diagnostic();
        term::emit(&mut writer.lock(), &config, file, &diagnostic).unwrap();
    }
}

pub fn emit_errors_str<T: IntoDiagnostic>(
    file: &SourceFile,
    errs: impl Iterator<Item = T>,
) -> String {
    let mut writer = Buffer::no_color();
    let config = codespan_reporting::term::Config::default();
    for err in errs {
        let diagnostic = err.into_diagnostic();
        term::emit(&mut writer, &config, file, &diagnostic).unwrap();
    }
    String::from_utf8(writer.into_inner()).unwrap()
}
