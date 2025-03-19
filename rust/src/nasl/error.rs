use std::ops::Range;

use codespan_reporting::diagnostic::Diagnostic;
use codespan_reporting::diagnostic::Label;
use codespan_reporting::term;
use codespan_reporting::term::termcolor::Buffer;
use codespan_reporting::term::termcolor::ColorChoice;
use codespan_reporting::term::termcolor::StandardStream;

use super::code::SourceFile;
use super::syntax::CharIndex;

#[derive(Clone, Debug)]
pub struct Span {
    start: CharIndex,
    end: CharIndex,
}

impl Span {
    pub(crate) fn new(start: CharIndex, end: CharIndex) -> Self {
        Self { start, end }
    }
}

impl Into<Range<usize>> for Span {
    fn into(self) -> Range<usize> {
        self.start.0..self.end.0
    }
}

pub trait AsCodespanError {
    fn span(&self) -> Span;
    fn message(&self) -> String;
}

pub fn emit_errors<T: AsCodespanError>(file: &SourceFile, errs: impl Iterator<Item = T>) {
    let writer = StandardStream::stderr(ColorChoice::Always);
    let config = codespan_reporting::term::Config::default();
    for err in errs {
        let diagnostic = Diagnostic::error()
            .with_message(&err.message())
            .with_labels(vec![
                Label::primary((), err.span()).with_message(&err.message()),
            ]);
        term::emit(&mut writer.lock(), &config, file, &diagnostic).unwrap();
    }
}

pub fn emit_errors_str<T: AsCodespanError>(
    file: &SourceFile,
    errs: impl Iterator<Item = T>,
) -> String {
    let mut writer = Buffer::no_color();
    let config = codespan_reporting::term::Config::default();
    for err in errs {
        let diagnostic = Diagnostic::error()
            .with_message(&err.message())
            .with_labels(vec![
                Label::primary((), err.span()).with_message(&err.message()),
            ]);
        term::emit(&mut writer, &config, file, &diagnostic).unwrap();
    }
    String::from_utf8(writer.into_inner()).unwrap()
}
