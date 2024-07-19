use nasl_syntax::NaslValue;

/// A type that can be converted to a NaslValue.
pub trait ToNaslValue {
    /// Perform the conversion
    fn to_nasl_value(self) -> NaslValue;
}

impl ToNaslValue for NaslValue {
    fn to_nasl_value(self) -> NaslValue {
        self
    }
}

impl ToNaslValue for usize {
    fn to_nasl_value(self) -> NaslValue {
        NaslValue::Number(self as i64)
    }
}

impl ToNaslValue for i64 {
    fn to_nasl_value(self) -> NaslValue {
        NaslValue::Number(self)
    }
}

impl ToNaslValue for String {
    fn to_nasl_value(self) -> NaslValue {
        NaslValue::String(self)
    }
}

impl<T: ToNaslValue> ToNaslValue for Option<T> {
    fn to_nasl_value(self) -> NaslValue {
        match self {
            Some(x) => x.to_nasl_value(),
            None => NaslValue::Null,
        }
    }
}
