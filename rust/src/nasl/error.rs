use std::ops::Range;

use codespan_reporting::diagnostic::Diagnostic;
use codespan_reporting::diagnostic::Label;
use codespan_reporting::term;
use codespan_reporting::term::termcolor::ColorChoice;
use codespan_reporting::term::termcolor::StandardStream;

use super::code::SourceFile;

pub trait AsCodespanError {
    fn range(&self) -> Range<usize>;
    fn message(&self) -> String;
}

pub fn emit_errors<T: AsCodespanError>(file: &SourceFile, errs: impl Iterator<Item = T>) {
    let writer = StandardStream::stderr(ColorChoice::Always);
    let config = codespan_reporting::term::Config::default();
    for err in errs {
        let diagnostic = Diagnostic::error()
            .with_message(&err.message())
            .with_labels(vec![
                Label::primary((), err.range()).with_message(&err.message())
            ]);
        term::emit(&mut writer.lock(), &config, file, &diagnostic).unwrap();
    }
}
