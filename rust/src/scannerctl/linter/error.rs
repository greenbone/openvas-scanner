use scannerlib::nasl::{
    error::{AsCodespanError, Level, Span},
    syntax::ParseError,
};

pub(super) struct LintMsg {
    span: Span,
    message: String,
    level: Level,
}

impl From<ParseError> for LintMsg {
    fn from(value: ParseError) -> Self {
        Self {
            span: value.span,
            message: value.kind.to_string(),
            level: Level::Error,
        }
    }
}

impl AsCodespanError for LintMsg {
    fn span(&self) -> Span {
        self.span
    }

    fn message(&self) -> String {
        self.message.clone()
    }

    fn level(&self) -> Level {
        self.level
    }
}
